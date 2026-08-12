# SPDX-License-Identifier: Apache-2.0
# Format references:
# - https://github.com/YuehaiTeam/kachina-installer
# - https://github.com/YuehaiTeam/kachina-installer/blob/main/src-tauri/src/local.rs
# - https://github.com/YuehaiTeam/kachina-installer/blob/main/src-tauri/src/builder/pack.rs
# - https://github.com/YuehaiTeam/kachina-installer/blob/main/src-tauri/src/installer/registry.rs
#
# The upstream repository did not declare a license when this parser was written. This file is an
# independent implementation based on observed binary structures and documented runtime behavior;
# it does not copy upstream source code.
#
# Kachina installer structures consumed by this parser:
#
#   native PE installer/updater
#   +-- DOS stub
#   |   `-- "!KachinaInstaller!" + five big-endian UInt32 index fields
#   +-- PE sections and resources
#   `-- appended record stream
#       +-- legacy record: "!INS" + NameLength + Name + ContentLength + Content
#       `-- indexed record: "!IN\0" + NameLength + Name + ContentLength + Content
#           +-- \0CONFIG: UTF-8 JSON installer configuration
#           +-- \0IMAGE: optional UI image
#           +-- \0INDEX: repeated name/size/relative-offset records
#           +-- \0META: UTF-8 JSON payload metadata
#           +-- hash-named Zstandard payload records
#           +-- fromHash_toHash compressed HDiff patch records
#           `-- optional raw runtime-installer records appended after packing
#
# Record-relative layout:
#
#   Offset  Size      Field
#   ------  --------  ----------------------------------------------------------
#   0x00           4  Magic: 21 49 4E 00 ("!IN\0") or legacy 21 49 4E 53 ("!INS")
#   0x04           2  UTF-8 name byte length, unsigned big-endian
#   0x06  NameLength  UTF-8 name
#   ...            4  Content byte length, unsigned big-endian
#   ...       Length  Content bytes
#
# Index offsets point to record content relative to the first appended record. The parser validates
# every available index entry against the sequential record stream but retains appended records that
# are intentionally absent from the index.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:KachinaCurrentMagic = [byte[]](0x21, 0x49, 0x4E, 0x00)
$Script:KachinaLegacyMagic = [byte[]](0x21, 0x49, 0x4E, 0x53)
$Script:KachinaPreIndexMagic = [Text.Encoding]::ASCII.GetBytes('!KachinaInstaller!')
$Script:KachinaUtf8 = [Text.UTF8Encoding]::new($false, $true)
$Script:KachinaMaximumNameBytes = 4096
$Script:KachinaMaximumRecords = 65536
$Script:KachinaMaximumConfigBytes = 4194304
$Script:KachinaMaximumMetadataBytes = 67108864
$Script:KachinaMaximumIndexBytes = 67108864
$Script:KachinaMaximumRecordSearchBytes = 67108864L
$Script:KachinaMaximumAnalysisFiles = 256
$Script:KachinaMaximumAnalysisBytes = 536870912L

function Get-KachinaMapValue {
  <#
  .SYNOPSIS
    Read a named value from a JSON dictionary without relying on truthiness.
  .PARAMETER Map
    IDictionary or object produced by ConvertFrom-Json.
  .PARAMETER Name
    Exact source field name.
  .PARAMETER DefaultValue
    Value returned when the source field is absent.
  #>
  param (
    $Map,
    [Parameter(Mandatory)][string]$Name,
    $DefaultValue = $null
  )

  if ($Map -is [Collections.IDictionary]) {
    if ($Map.Contains($Name)) { return $Map[$Name] }
    return $DefaultValue
  }
  if ($null -ne $Map) {
    $Property = $Map.PSObject.Properties[$Name]
    if ($Property) { return $Property.Value }
  }
  return $DefaultValue
}

function Read-KachinaJsonRecord {
  <#
  .SYNOPSIS
    Decode a bounded UTF-8 JSON record from a caller-owned installer stream.
  .PARAMETER Stream
    Readable, seekable installer stream. Its position is restored by the shared random-access reader.
  .PARAMETER Record
    Kachina record containing absolute content offset and byte length.
  .PARAMETER MaximumBytes
    Hard allocation limit for the JSON content.
  #>
  [OutputType([Collections.IDictionary])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Record,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes
  )

  if ([long]$Record.Length -gt $MaximumBytes) { throw "Kachina JSON record '$($Record.DisplayName)' exceeds the $MaximumBytes-byte limit." }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Record.DataOffset -Count ([int]$Record.Length)
  try {
    $Text = $Script:KachinaUtf8.GetString($Bytes)
    $Value = $Text | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop
  } catch {
    throw "Kachina JSON record '$($Record.DisplayName)' is invalid: $($_.Exception.Message)"
  }
  if ($Value -isnot [Collections.IDictionary]) { throw "Kachina JSON record '$($Record.DisplayName)' must contain an object." }
  return $Value
}

function Read-KachinaRecordSequence {
  <#
  .SYNOPSIS
    Parse one contiguous Kachina TLV sequence from a known absolute offset.
  .PARAMETER Stream
    Readable, seekable installer stream. The parser uses random-access reads and restores its position.
  .PARAMETER StartOffset
    Absolute offset of the first TLV magic.
  .PARAMETER Magic
    Four-byte magic shared by every record in this generation.
  .PARAMETER MaximumRecords
    Hard record-count limit.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$StartOffset,
    [Parameter(Mandatory)][ValidateCount(4, 4)][byte[]]$Magic,
    [ValidateRange(1, 65536)][int]$MaximumRecords = $Script:KachinaMaximumRecords
  )

  $Records = [Collections.Generic.List[object]]::new()
  $Offset = $StartOffset
  while ($Offset -lt $Stream.Length) {
    if ($Records.Count -ge $MaximumRecords) { throw "The Kachina record stream exceeds the $MaximumRecords-record limit." }
    if ($Stream.Length - $Offset -lt 10) { throw "The Kachina record header at offset $Offset is truncated." }

    $ObservedMagic = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 4
    if (-not (Test-BinarySequence -Left $ObservedMagic -Right $Magic)) {
      throw "Unexpected data follows the Kachina record stream at offset $Offset."
    }
    $NameLength = [int](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 2 -Endian BigEndian)
    if ($NameLength -le 0 -or $NameLength -gt $Script:KachinaMaximumNameBytes) {
      throw "The Kachina record at offset $Offset has an invalid $NameLength-byte name."
    }
    $HeaderLength = 10L + $NameLength
    if ($HeaderLength -gt $Stream.Length - $Offset) { throw "The Kachina record name at offset $Offset is truncated." }
    $NameBytes = Read-BinaryBytes -Stream $Stream -Offset ($Offset + 6) -Count $NameLength
    try { $Name = $Script:KachinaUtf8.GetString($NameBytes) } catch { throw "The Kachina record name at offset $Offset is not valid UTF-8." }
    $LengthOffset = $Offset + 6 + $NameLength
    $ContentLength = [long](Read-BinaryInteger -Stream $Stream -Offset $LengthOffset -Size 4 -Endian BigEndian)
    $DataOffset = $LengthOffset + 4
    if ($ContentLength -gt $Stream.Length - $DataOffset) { throw "Kachina record '$($Name.Replace("`0", '\0'))' extends beyond the installer." }

    $Records.Add([pscustomobject][ordered]@{
        Name         = $Name
        DisplayName  = $Name.Replace("`0", '\0')
        RawOffset    = $Offset
        HeaderLength = $HeaderLength
        DataOffset   = $DataOffset
        Length       = $ContentLength
        EndOffset    = $DataOffset + $ContentLength
      })
    $Offset = $DataOffset + $ContentLength
  }
  return @($Records)
}

function Get-KachinaPreIndex {
  <#
  .SYNOPSIS
    Read the optional Kachina DOS-stub pre-index.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER SearchEnd
    Exclusive absolute boundary of the PE stub search.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$SearchEnd
  )

  $Length = [Math]::Min($SearchEnd, 4096L)
  if ($Length -lt 38) { return $null }
  $Offsets = @(Find-BinaryPattern -Stream $Stream -Pattern $Script:KachinaPreIndexMagic -StartOffset 0 -Length $Length -Maximum 2)
  if ($Offsets.Count -ne 1) { return $null }
  $Offset = [long]$Offsets[0]
  if ($Offset + 38 -gt $Stream.Length) { return $null }
  $Values = [uint32[]]::new(5)
  for ($Index = 0; $Index -lt 5; $Index++) {
    $Values[$Index] = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 18 + ($Index * 4)) -Size 4 -Endian BigEndian)
  }
  [pscustomobject][ordered]@{
    Offset     = $Offset
    FieldOffset = $Offset + 18
    Values     = $Values
    IsCleared  = -not ($Values | Where-Object { $_ -ne 0 })
  }
}

function Find-KachinaRecordSequence {
  <#
  .SYNOPSIS
    Locate and validate the Kachina record stream at or after the PE overlay boundary.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER OverlayOffset
    Offset immediately after the final PE section.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$OverlayOffset
  )

  $Candidates = [Collections.Generic.SortedSet[long]]::new()
  $null = $Candidates.Add($OverlayOffset)
  $SearchLength = [Math]::Min($Script:KachinaMaximumRecordSearchBytes, $Stream.Length - $OverlayOffset)
  if ($SearchLength -gt 0) {
    foreach ($Magic in @($Script:KachinaCurrentMagic, $Script:KachinaLegacyMagic)) {
      foreach ($Offset in Find-BinaryPattern -Stream $Stream -Pattern $Magic -StartOffset $OverlayOffset -Length $SearchLength -Maximum 32) {
        $null = $Candidates.Add([long]$Offset)
      }
    }
  }

  foreach ($Offset in $Candidates) {
    if ($Offset + 4 -gt $Stream.Length) { continue }
    $Magic = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 4
    $IsCurrent = Test-BinarySequence -Left $Magic -Right $Script:KachinaCurrentMagic
    $IsLegacy = Test-BinarySequence -Left $Magic -Right $Script:KachinaLegacyMagic
    if (-not $IsCurrent -and -not $IsLegacy) { continue }
    try {
      $Records = @(Read-KachinaRecordSequence -Stream $Stream -StartOffset $Offset -Magic $Magic)
      if ($Records.Count -eq 0) { continue }
      $ConfigName = $IsLegacy ? '.config.json' : "`0CONFIG"
      $MetadataName = $IsLegacy ? '.metadata.json' : "`0META"
      $Config = @($Records | Where-Object Name -CEQ $ConfigName)
      $Metadata = @($Records | Where-Object Name -CEQ $MetadataName)
      if ($Config.Count -ne 1) { continue }
      if ($IsLegacy -and $Metadata.Count -ne 1) { continue }
      return [pscustomobject]@{ StartOffset = $Offset; Magic = $Magic; IsLegacy = $IsLegacy; Records = $Records }
    } catch {
      continue
    }
  }
  throw 'The PE does not contain a supported Kachina record stream.'
}

function Read-KachinaIndex {
  <#
  .SYNOPSIS
    Parse and cross-check the compact Kachina index record.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Record
    The \0INDEX TLV.
  .PARAMETER RecordStart
    Absolute base used by index content offsets.
  .PARAMETER Records
    Sequential TLV records used as the validation authority.
  .PARAMETER Warnings
    Diagnostic list receiving non-fatal index disagreements.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Record,
    [Parameter(Mandatory)][long]$RecordStart,
    [Parameter(Mandatory)][object[]]$Records,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[string]]$Warnings
  )

  if ($Record.Length -gt $Script:KachinaMaximumIndexBytes) { throw "The Kachina index exceeds the $Script:KachinaMaximumIndexBytes-byte limit." }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Record.DataOffset -Count ([int]$Record.Length)
  $IndexStream = [IO.MemoryStream]::new($Bytes, $false)
  $Entries = [Collections.Generic.List[object]]::new()
  # Index validation is potentially exercised for every payload file. Build one
  # exact range set instead of scanning the physical catalog for every entry.
  $RecordRanges = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($PhysicalRecord in $Records) { $null = $RecordRanges.Add("$($PhysicalRecord.Name)`u{001F}$($PhysicalRecord.DataOffset)`u{001F}$($PhysicalRecord.Length)") }
  try {
    while ($IndexStream.Position -lt $IndexStream.Length) {
      if ($Entries.Count -ge $Script:KachinaMaximumRecords) { throw "The Kachina index exceeds the $Script:KachinaMaximumRecords-entry limit." }
      $NameLength = [int](Read-BinarySequentialInteger -Stream $IndexStream -Size 1)
      if ($NameLength -le 0 -or $NameLength -gt $Script:KachinaMaximumNameBytes) { throw "The Kachina index contains an invalid $NameLength-byte name." }
      if ($IndexStream.Length - $IndexStream.Position -lt $NameLength + 8) { throw 'The Kachina index contains a truncated entry.' }
      $NameBytes = [byte[]]::new($NameLength)
      $null = $IndexStream.Read($NameBytes, 0, $NameLength)
      try { $Name = $Script:KachinaUtf8.GetString($NameBytes) } catch { throw 'The Kachina index contains a non-UTF-8 name.' }
      $Size = [long](Read-BinarySequentialInteger -Stream $IndexStream -Size 4 -Endian BigEndian)
      $RelativeOffset = [long](Read-BinarySequentialInteger -Stream $IndexStream -Size 4 -Endian BigEndian)
      $AbsoluteOffset = $RecordStart + $RelativeOffset
      $IsValidated = $RecordRanges.Contains("$Name`u{001F}$AbsoluteOffset`u{001F}$Size")
      if (-not $IsValidated) { $Warnings.Add("Kachina index entry '$($Name.Replace("`0", '\0'))' does not match a sequential record boundary.") }
      $Entries.Add([pscustomobject][ordered]@{ Name = $Name; DisplayName = $Name.Replace("`0", '\0'); Size = $Size; RelativeOffset = $RelativeOffset; AbsoluteOffset = $AbsoluteOffset; IsValidated = $IsValidated })
    }
  } finally { $IndexStream.Dispose() }
  return @($Entries)
}

function Get-KachinaAnalysisContext {
  <#
  .SYNOPSIS
    Build one reusable Kachina layout and metadata context from an open installer.
  .PARAMETER File
    Resolved installer FileInfo.
  .PARAMETER Stream
    Readable, seekable caller-owned stream. The function leaves it open and restores random-read positions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][IO.Stream]$Stream
  )

  $Warnings = [Collections.Generic.List[string]]::new()
  $Layout = Get-PELayout -Stream $Stream
  if (-not $Layout) { throw 'The file is not a valid PE image.' }
  $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
  if ($OverlayOffset -le 0 -or $OverlayOffset -ge $Stream.Length) { throw 'The PE has no appended Kachina data.' }
  $Sequence = Find-KachinaRecordSequence -Stream $Stream -OverlayOffset $OverlayOffset
  $Records = @($Sequence.Records)
  $PreIndex = Get-KachinaPreIndex -Stream $Stream -SearchEnd $Sequence.StartOffset

  $ConfigName = $Sequence.IsLegacy ? '.config.json' : "`0CONFIG"
  $MetadataName = $Sequence.IsLegacy ? '.metadata.json' : "`0META"
  $ConfigRecord = @($Records | Where-Object Name -CEQ $ConfigName)
  $MetadataRecord = @($Records | Where-Object Name -CEQ $MetadataName)
  $IndexRecord = @($Records | Where-Object Name -CEQ "`0INDEX")
  if ($ConfigRecord.Count -ne 1 -or $MetadataRecord.Count -gt 1 -or $IndexRecord.Count -gt 1) { throw 'The Kachina control records are absent or ambiguous.' }
  $Config = Read-KachinaJsonRecord -Stream $Stream -Record $ConfigRecord[0] -MaximumBytes $Script:KachinaMaximumConfigBytes
  foreach ($RequiredName in 'appName', 'publisher', 'regName', 'exeName') {
    if ([string]::IsNullOrWhiteSpace([string](Get-KachinaMapValue -Map $Config -Name $RequiredName))) { throw "Kachina configuration field '$RequiredName' is absent or empty." }
  }
  $Metadata = if ($MetadataRecord.Count -eq 1) { Read-KachinaJsonRecord -Stream $Stream -Record $MetadataRecord[0] -MaximumBytes $Script:KachinaMaximumMetadataBytes } else { $null }

  $Generation = if ($Sequence.IsLegacy) {
    'LegacyScan'
  } elseif ($IndexRecord.Count -eq 0 -and $MetadataRecord.Count -eq 0) {
    'ConfigOnly'
  } elseif ($Records[0].Name -ceq "`0INDEX") {
    'EarlyIndexed'
  } else {
    'Indexed'
  }
  if (-not $Sequence.IsLegacy -and $Records[0].Name -notin "`0CONFIG", "`0INDEX") { throw 'The Kachina indexed stream does not begin with CONFIG or INDEX.' }
  if ($Generation -eq 'ConfigOnly' -and $Metadata) { $Warnings.Add('Kachina pre-index fields are cleared even though embedded metadata remains available.') }

  $Index = if ($IndexRecord.Count -eq 1) { @(Read-KachinaIndex -Stream $Stream -Record $IndexRecord[0] -RecordStart $Sequence.StartOffset -Records $Records -Warnings $Warnings) } else { @() }
  if ($Index | Where-Object { -not $_.IsValidated }) {
    throw 'The Kachina index contains an entry that does not resolve to a sequential TLV boundary.'
  }
  if ($PreIndex -and -not $PreIndex.IsCleared) {
    if ([long]$PreIndex.Values[0] -ne $Sequence.StartOffset) { $Warnings.Add("Kachina pre-index base offset $($PreIndex.Values[0]) differs from the validated record start $($Sequence.StartOffset).") }
    $ConfigRawLength = $ConfigRecord[0].HeaderLength + $ConfigRecord[0].Length
    $ImageRecord = $Records | Where-Object { $_.Name -ceq "`0IMAGE" -or $_.Name -ceq '.image' } | Select-Object -First 1
    $ImageRawLength = $ImageRecord ? ($ImageRecord.HeaderLength + $ImageRecord.Length) : 0L
    $IndexRawLength = $IndexRecord.Count -eq 1 ? ($IndexRecord[0].HeaderLength + $IndexRecord[0].Length) : 0L
    $MetadataRawLength = $MetadataRecord.Count -eq 1 ? ($MetadataRecord[0].HeaderLength + $MetadataRecord[0].Length) : 0L
    $Expected = $Generation -eq 'EarlyIndexed' ? @($IndexRawLength, $ConfigRawLength, $ImageRawLength, $MetadataRawLength) : @($ConfigRawLength, $ImageRawLength, $IndexRawLength, $MetadataRawLength)
    for ($IndexNumber = 0; $IndexNumber -lt 4; $IndexNumber++) {
      $ActualValue = [long]$PreIndex.Values[$IndexNumber + 1]
      if ($ActualValue -eq $Expected[$IndexNumber]) { continue }
      # The first indexed builder double-counted the INDEX TLV header in this one pre-index field.
      if ($Generation -eq 'EarlyIndexed' -and $IndexNumber -eq 0 -and $ActualValue -eq $Expected[0] + $IndexRecord[0].HeaderLength) { continue }
      $Warnings.Add("Kachina pre-index field $($IndexNumber + 1) is $ActualValue bytes; the parsed record layout yields $($Expected[$IndexNumber]) bytes.")
    }
  }

  $GeneratedExecutableEnd = $ConfigRecord[0].EndOffset
  $Image = $Records | Where-Object { $_.Name -ceq "`0IMAGE" -or $_.Name -ceq '.image' } | Select-Object -First 1
  if ($Image) { $GeneratedExecutableEnd = $Image.EndOffset }
  [pscustomobject][ordered]@{
    File                   = $File
    Stream                 = $Stream
    Layout                 = $Layout
    OverlayOffset          = $OverlayOffset
    RecordStart            = $Sequence.StartOffset
    Records                = $Records
    ConfigRecord           = $ConfigRecord[0]
    MetadataRecord         = $MetadataRecord | Select-Object -First 1
    IndexRecord            = $IndexRecord | Select-Object -First 1
    ImageRecord            = $Image
    Config                 = $Config
    Metadata               = $Metadata
    Index                  = $Index
    PreIndex               = $PreIndex
    FormatGeneration       = $Generation
    GeneratedExecutableEnd = $GeneratedExecutableEnd
    Warnings               = @($Warnings)
  }
}

function Get-KachinaMetadataHash {
  <#
  .SYNOPSIS
    Select the source-defined record identity from one metadata item.
  .PARAMETER Item
    One metadata `hashed` item or one side of a patch record.
  #>
  param ([Parameter(Mandatory)]$Item)
  $Md5 = [string](Get-KachinaMapValue -Map $Item -Name 'md5')
  if (-not [string]::IsNullOrWhiteSpace($Md5)) { return [pscustomobject]@{ Value = $Md5; Algorithm = 'MD5' } }
  $Xxh = [string](Get-KachinaMapValue -Map $Item -Name 'xxh')
  if (-not [string]::IsNullOrWhiteSpace($Xxh)) { return [pscustomobject]@{ Value = $Xxh; Algorithm = 'XXH (source-defined)' } }
  return $null
}

function Get-KachinaPayloadCatalog {
  <#
  .SYNOPSIS
    Project metadata paths onto their compressed TLV records.
  .PARAMETER Context
    Reusable Kachina analysis context.
  .PARAMETER Warnings
    Diagnostic list receiving missing or malformed payload evidence.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[string]]$Warnings
  )

  if (-not $Context.Metadata) { return @() }
  $RecordsByName = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  foreach ($Record in $Context.Records) {
    if (-not $RecordsByName.ContainsKey($Record.Name)) { $RecordsByName[$Record.Name] = $Record }
  }
  $Catalog = [Collections.Generic.List[object]]::new()
  foreach ($Item in @(Get-KachinaMapValue -Map $Context.Metadata -Name 'hashed' -DefaultValue @())) {
    $Path = [string](Get-KachinaMapValue -Map $Item -Name 'file_name')
    $Hash = Get-KachinaMetadataHash -Item $Item
    $Size = Get-KachinaMapValue -Map $Item -Name 'size'
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $Hash -or $null -eq $Size) {
      $Warnings.Add('Kachina metadata contains a payload item without a path, size, or record hash.')
      continue
    }
    $Record = $RecordsByName[$Hash.Value]
    if (-not $Record) { $Warnings.Add("Kachina payload record '$($Hash.Value)' for '$Path' is absent.") }
    $Catalog.Add([pscustomobject][ordered]@{
        Path             = $Path.Replace('/', '\')
        Hash             = $Hash.Value
        HashAlgorithm    = $Hash.Algorithm
        ExpectedSize     = [long]$Size
        CompressedSize   = $Record ? [long]$Record.Length : $null
        RecordOffset     = $Record ? [long]$Record.RawOffset : $null
        DataOffset       = $Record ? [long]$Record.DataOffset : $null
        IsEmbedded       = $null -ne $Record
        Compression      = 'Zstandard'
      })
  }
  return @($Catalog)
}

function Get-KachinaPatchCatalog {
  <#
  .SYNOPSIS
    Project Kachina HDiff patch metadata without treating patches as installed files.
  .PARAMETER Context
    Reusable Kachina analysis context containing metadata and physical TLVs.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)]$Context)

  if (-not $Context.Metadata) { return @() }
  foreach ($Patch in @(Get-KachinaMapValue -Map $Context.Metadata -Name 'patches' -DefaultValue @())) {
    $From = Get-KachinaMetadataHash -Item (Get-KachinaMapValue -Map $Patch -Name 'from')
    $To = Get-KachinaMetadataHash -Item (Get-KachinaMapValue -Map $Patch -Name 'to')
    if (-not $From -or -not $To) { continue }
    $RecordName = "$($From.Value)_$($To.Value)"
    $Record = $Context.Records | Where-Object Name -CEQ $RecordName | Select-Object -First 1
    [pscustomobject][ordered]@{
      Path           = [string](Get-KachinaMapValue -Map $Patch -Name 'file_name')
      RecordName     = $RecordName
      FromHash       = $From.Value
      ToHash         = $To.Value
      ExpectedSize   = [long](Get-KachinaMapValue -Map $Patch -Name 'size' -DefaultValue 0)
      CompressedSize = $Record ? [long]$Record.Length : $null
      IsEmbedded     = $null -ne $Record
      Format         = 'HDiffPatch'
    }
  }
}

function Export-KachinaPayloadItem {
  <#
  .SYNOPSIS
    Decompress one metadata-backed payload record into a validated path.
  .PARAMETER Context
    Reusable context containing the caller-owned source stream.
  .PARAMETER Item
    Payload catalog item with absolute compressed range and declared output size.
  .PARAMETER DestinationPath
    Exact resolved output path.
  .PARAMETER MaximumBytes
    Remaining aggregate output allowance.
  #>
  [OutputType([IO.FileInfo])]
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)]$Item,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  if (-not $Item.IsEmbedded) { throw "Kachina payload record '$($Item.Hash)' is not embedded." }
  if ($Item.ExpectedSize -gt $MaximumBytes) { throw "Kachina payload '$($Item.Path)' exceeds the remaining $MaximumBytes-byte output limit." }
  $Parent = Split-Path -Parent $DestinationPath
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $CompressedInput = New-BoundedReadStream -Stream $Context.Stream -Offset $Item.DataOffset -Length $Item.CompressedSize -LeaveOpen
  $Output = $null
  try {
    $Output = [IO.File]::Open($DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $null = Expand-InstallerCompressedStream -Algorithm Zstd -Stream $CompressedInput -Destination $Output -MaximumBytes $MaximumBytes -CompressedSize $Item.CompressedSize -UncompressedSize $Item.ExpectedSize
  } catch {
    if ($Output) { $Output.Dispose(); $Output = $null }
    Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
    throw
  } finally {
    if ($Output) { $Output.Dispose() }
    $CompressedInput.Dispose()
  }
  $File = Get-Item -LiteralPath $DestinationPath -Force
  if ($Item.HashAlgorithm -eq 'MD5') {
    # MD5 is used only to validate the exact legacy digest stored by Kachina;
    # this is an integrity comparison, not a security decision.
    $ActualHash = (Get-FileHash -LiteralPath $File.FullName -Algorithm MD5).Hash
    if ($ActualHash -ine $Item.Hash) { Remove-Item -LiteralPath $File.FullName -Force; throw "Kachina payload '$($Item.Path)' failed its MD5 check." }
  }
  return $File
}

function Export-KachinaPayloadSelection {
  <#
  .SYNOPSIS
    Expand selected installed payload paths with aggregate and collision limits.
  .PARAMETER Context
    Reusable context containing the caller-owned installer stream.
  .PARAMETER Catalog
    Metadata-backed installed-file catalog. Empty catalogs are valid for config-only media.
  .PARAMETER DestinationPath
    Resolved extraction root.
  .PARAMETER Name
    Wildcard matched against installed relative paths.
  .PARAMETER CollisionAction
    Existing or duplicate destination behavior.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit in bytes.
  .PARAMETER MaximumEntries
    Maximum selected installed-file count.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Catalog,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Rename',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184,
    [ValidateRange(1, 65536)][int]$MaximumEntries = $Script:KachinaMaximumRecords
  )

  $Files = [Collections.Generic.List[IO.FileInfo]]::new()
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ExpandedBytes = 0L
  $Selected = @($Catalog | Where-Object { Test-ExtractionPattern -Path $_.Path -Pattern $Name })
  if ($Selected.Count -gt $MaximumEntries) { throw "The Kachina selection exceeds the $MaximumEntries-entry limit." }
  $FirstOutputByHash = [Collections.Generic.Dictionary[string, IO.FileInfo]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in $Selected) {
    if ($Item.ExpectedSize -gt $MaximumExpandedBytes - $ExpandedBytes) { throw "The Kachina selection exceeds the $MaximumExpandedBytes-byte output limit." }
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.Path -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if (-not $Target.ShouldWrite) { continue }
    $FirstOutput = $FirstOutputByHash[$Item.Hash]
    if ($FirstOutput) {
      $Parent = Split-Path -Parent $Target.Path
      if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
      $Source = [IO.File]::Open($FirstOutput.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
      $Destination = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $null = Copy-BoundedStream -Source $Source -Destination $Destination -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes) -ExpectedBytes $FirstOutput.Length } finally { $Destination.Dispose(); $Source.Dispose() }
      $File = Get-Item -LiteralPath $Target.Path -Force
    } else {
      $File = Export-KachinaPayloadItem -Context $Context -Item $Item -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes)
      $FirstOutputByHash[$Item.Hash] = $File
    }
    $ExpandedBytes += $File.Length
    $Files.Add($File)
  }
  [pscustomobject]@{ Files = @($Files); ExpandedBytes = $ExpandedBytes; EntryCount = $Files.Count }
}

function Export-KachinaGeneratedExecutable {
  <#
  .SYNOPSIS
    Reconstruct an installed Kachina updater or uninstaller from the configured PE prefix.
  .PARAMETER Context
    Reusable context whose stream supplies the PE, configuration, and optional image prefix.
  .PARAMETER DestinationPath
    Exact resolved output path.
  .PARAMETER MaximumBytes
    Remaining aggregate output allowance.
  #>
  [OutputType([IO.FileInfo])]
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][long]$MaximumBytes
  )

  if ($Context.GeneratedExecutableEnd -gt $MaximumBytes) { throw "The generated Kachina executable exceeds the remaining $MaximumBytes-byte limit." }
  $Parent = Split-Path -Parent $DestinationPath
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $Output = [IO.File]::Open($DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    Copy-BinaryStreamRange -Source $Context.Stream -Destination $Output -Offset 0 -Length $Context.GeneratedExecutableEnd
    # Kachina leaves the marker text in place and clears only the five index fields in installed tools.
    if ($Context.PreIndex) {
      $Output.Position = $Context.PreIndex.FieldOffset
      $Output.Write([byte[]]::new(20), 0, 20)
    }
  } finally { $Output.Dispose() }
  return Get-Item -LiteralPath $DestinationPath -Force
}

function Get-KachinaPayloadEvidence {
  <#
  .SYNOPSIS
    Analyze the configured main executable and bounded related files without retaining payloads.
  .PARAMETER Context
    Reusable Kachina analysis context.
  .PARAMETER Catalog
    Installed payload projection used for selective materialization.
  .PARAMETER ExeName
    Configured application executable name.
  .PARAMETER Warnings
    Diagnostic list receiving bounded-analysis failures.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Catalog,
    [Parameter(Mandatory)][string]$ExeName,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[string]]$Warnings
  )

  $Main = $Catalog | Where-Object { $_.Path -ieq $ExeName -or [IO.Path]::GetFileName($_.Path) -ieq [IO.Path]::GetFileName($ExeName) } | Select-Object -First 1
  if (-not $Main -or -not $Main.IsEmbedded) { return [pscustomobject]@{ Architectures = @(); ArchitectureInfo = $null; DependencyInfo = $null } }
  $MainDirectory = [IO.Path]::GetDirectoryName($Main.Path)
  $Related = @($Catalog | Where-Object {
      $_.IsEmbedded -and $_ -ne $Main -and [IO.Path]::GetDirectoryName($_.Path) -ieq $MainDirectory -and [IO.Path]::GetExtension($_.Path) -in '.dll', '.json'
    } | Select-Object -First ($Script:KachinaMaximumAnalysisFiles - 1))
  $Selection = @($Main) + $Related
  $DeclaredBytes = ($Selection | Measure-Object ExpectedSize -Sum).Sum
  if ($DeclaredBytes -gt $Script:KachinaMaximumAnalysisBytes) {
    $Warnings.Add("Kachina payload analysis requires $DeclaredBytes bytes, above the $Script:KachinaMaximumAnalysisBytes-byte analysis limit.")
    return [pscustomobject]@{ Architectures = @(); ArchitectureInfo = $null; DependencyInfo = $null }
  }
  $TemporaryDirectory = New-TempFolder
  try {
    $Expanded = Export-KachinaPayloadSelection -Context $Context -Catalog $Selection -DestinationPath $TemporaryDirectory -CollisionAction Rename -MaximumExpandedBytes $Script:KachinaMaximumAnalysisBytes -MaximumEntries $Script:KachinaMaximumAnalysisFiles
    $MainPath = Join-Path $TemporaryDirectory $Main.Path
    if (-not (Test-Path -LiteralPath $MainPath -PathType Leaf)) { return [pscustomobject]@{ Architectures = @(); ArchitectureInfo = $null; DependencyInfo = $null } }
    $RelatedFiles = @($Expanded.Files | Where-Object FullName -NE ([IO.Path]::GetFullPath($MainPath)) | Select-Object -ExpandProperty FullName)
    $ArchitectureInfo = $null
    $DependencyInfo = $null
    try { $ArchitectureInfo = Get-PEArchitectureInfo -Path $MainPath -RelatedFile @($RelatedFiles | Where-Object { [IO.Path]::GetExtension($_) -ieq '.dll' }) } catch { $Warnings.Add("Kachina payload architecture analysis failed: $($_.Exception.Message)") }
    try { $DependencyInfo = Get-PEDependencyInfo -Path $MainPath -RelatedFile $RelatedFiles } catch { $Warnings.Add("Kachina payload dependency analysis failed: $($_.Exception.Message)") }
    [pscustomobject]@{ Architectures = if ($ArchitectureInfo) { @($ArchitectureInfo.RecommendedWinGetArchitectures) } else { @() }; ArchitectureInfo = $ArchitectureInfo; DependencyInfo = $DependencyInfo }
  } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-KachinaInfo {
  <#
  .SYNOPSIS
    Read Kachina configuration, payload, ARP, scope, switches, architecture, and dependency evidence.
  .PARAMETER Path
    Path to a legacy or indexed Kachina installer. The installer is opened once and never executed.
  .OUTPUTS
    A parser result using the shared installer identity/ARP contract with additive Kachina evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force -ErrorAction Stop
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Context = Get-KachinaAnalysisContext -File $File -Stream $Stream
      $Warnings = [Collections.Generic.List[string]]::new()
      foreach ($Warning in $Context.Warnings) { $Warnings.Add($Warning) }
      $Notices = [Collections.Generic.List[string]]::new()
      $UnresolvedFields = [Collections.Generic.List[string]]::new()
      $Config = $Context.Config
      $Metadata = $Context.Metadata
      $DisplayName = [string](Get-KachinaMapValue -Map $Config -Name 'appName')
      $Publisher = [string](Get-KachinaMapValue -Map $Config -Name 'publisher')
      $ProductCode = [string](Get-KachinaMapValue -Map $Config -Name 'regName')
      $ExeName = [string](Get-KachinaMapValue -Map $Config -Name 'exeName')
      $UninstallName = [string](Get-KachinaMapValue -Map $Config -Name 'uninstallName' -DefaultValue 'uninst.exe')
      $UpdaterName = [string](Get-KachinaMapValue -Map $Config -Name 'updaterName' -DefaultValue 'update.exe')
      $ProgramFilesPath = [string](Get-KachinaMapValue -Map $Config -Name 'programFilesPath' -DefaultValue 'KachinaInstaller')
      $UacStrategy = [string](Get-KachinaMapValue -Map $Config -Name 'uacStrategy' -DefaultValue 'prefer-admin')
      if ($UacStrategy -notin 'prefer-admin', 'prefer-user', 'force') { $Warnings.Add("Unknown Kachina UAC strategy '$UacStrategy'; supported scope evidence is conservative."); $UacStrategy = 'unknown' }
      $DisplayVersion = if ($Metadata) { [string](Get-KachinaMapValue -Map $Metadata -Name 'tag_name') } else { $null }
      if ([string]::IsNullOrWhiteSpace($DisplayVersion)) { $DisplayVersion = $null; $UnresolvedFields.Add('DisplayVersion') }
      if (-not $Metadata) { $UnresolvedFields.Add('PayloadFiles'); $Notices.Add('This is a config-only Kachina updater; target version and payload evidence require the configured source.') }

      $SupportedScopes = $UacStrategy -eq 'force' ? @('machine') : @('machine', 'user')
      $Scope = 'machine'
      if ($UacStrategy -ne 'force') { $Notices.Add("Kachina defaults to Program Files and machine scope; '$UacStrategy' can use user scope when -D selects an eligible user-writable path.") }
      $DefaultInstallLocation = '%ProgramFiles%\' + $ProgramFilesPath.TrimStart('\', '/')
      $UninstallString = "$DefaultInstallLocation\$UninstallName"
      $DisplayIcon = "$DefaultInstallLocation\$ExeName"
      $OuterArchitectureInfo = Get-PEArchitectureInfo -Path $File.FullName
      $RegistryView = $OuterArchitectureInfo.NativeArchitecture -eq 'x86' ? '32-bit' : ($OuterArchitectureInfo.NativeArchitecture -in 'x64', 'arm64' ? '64-bit' : 'default')

      $RegistryWrites = [Collections.Generic.List[object]]::new()
      $UninstallKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
      $EstimatedBytes = if ($Metadata) { (@(Get-KachinaMapValue -Map $Metadata -Name 'hashed' -DefaultValue @()) | Measure-Object -Property size -Sum).Sum } else { $null }
      $ArpValues = [ordered]@{
        DisplayName      = $DisplayName
        DisplayVersion   = $DisplayVersion
        UninstallString  = $UninstallString
        InstallLocation  = $DefaultInstallLocation
        DisplayIcon      = $DisplayIcon
        Publisher        = $Publisher
        NoModify         = 1
        NoRepair         = 1
      }
      if ($null -ne $EstimatedBytes) { $ArpValues['EstimatedSize'] = [uint32][Math]::Min([uint32]::MaxValue, [Math]::Floor([double]$EstimatedBytes / 1024)) }
      foreach ($Entry in $ArpValues.GetEnumerator()) {
        if ($null -eq $Entry.Value) { continue }
        $RegistryWrites.Add([pscustomobject]@{ Hive = 'HKEY_LOCAL_MACHINE'; Root = 'HKLM'; View = $RegistryView; Key = $UninstallKey; Name = $Entry.Key; Value = $Entry.Value; Type = $Entry.Value -is [int] ? 'REG_DWORD' : 'REG_SZ'; Source = 'Kachina built-in uninstall registration for the default machine route' })
      }
      $RegistryRoutes = [Collections.Generic.List[object]]::new()
      $RegistryRoutes.Add([pscustomobject]@{ Scope = 'machine'; Hive = 'HKEY_LOCAL_MACHINE'; Root = 'HKLM'; Condition = 'Installer process is elevated' })
      if ($UacStrategy -ne 'force') { $RegistryRoutes.Add([pscustomobject]@{ Scope = 'user'; Hive = 'HKEY_CURRENT_USER'; Root = 'HKCU'; Condition = 'Installer process is not elevated after -D selects an eligible user-writable path' }) }
      $AssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite @($RegistryWrites)
      foreach ($Warning in $AssociationInfo.Warnings) { $Warnings.Add("Kachina association analysis: $Warning") }

      $Catalog = @(Get-KachinaPayloadCatalog -Context $Context -Warnings $Warnings)
      $Patches = @(Get-KachinaPatchCatalog -Context $Context)
      $PayloadEvidence = Get-KachinaPayloadEvidence -Context $Context -Catalog $Catalog -ExeName $ExeName -Warnings $Warnings
      if (@($PayloadEvidence.Architectures).Count -eq 0) { $UnresolvedFields.Add('PayloadArchitecture') }
      $ConfiguredRuntimes = @((Get-KachinaMapValue -Map $Config -Name 'runtimes' -DefaultValue @()) | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      $EmbeddedRuntimePackages = @($Context.Records | Where-Object { $_.Name -match '^Microsoft\.(?:DotNet|VCRedist)\.' } | ForEach-Object { [pscustomobject]@{ PackageIdentifier = $_.Name; Offset = $_.DataOffset; Length = $_.Length; Delivery = 'Raw appended installer' } })
      $RuntimePackages = @($ConfiguredRuntimes | ForEach-Object {
          $Identifier = $_
          [pscustomobject]@{ PackageIdentifier = $Identifier; IsConfigured = $true; IsEmbedded = [bool]($EmbeddedRuntimePackages | Where-Object PackageIdentifier -CEQ $Identifier | Select-Object -First 1) }
        })
      if ($ConfiguredRuntimes.Count -gt 0) { $Notices.Add('Kachina can install its configured runtime prerequisites itself; dependency evidence is returned without mutating manifest Dependencies.') }

      $AppsAndFeaturesEntry = [ordered]@{ ProductCode = $ProductCode; DisplayName = $DisplayName; Publisher = $Publisher; InstallerType = 'exe' }
      if ($DisplayVersion) { $AppsAndFeaturesEntry.DisplayVersion = $DisplayVersion }
      $AppsAndFeaturesEntries = @($AppsAndFeaturesEntry)
      $CanExpand = $Catalog.Count -gt 0 -and -not ($Catalog | Where-Object { -not $_.IsEmbedded })
      $Source = Get-KachinaMapValue -Map $Config -Name 'source'
      if ($null -eq $Source) { $Source = Get-KachinaMapValue -Map $Config -Name 'dfsPath' }
      $Shortcuts = @(
        [pscustomobject]@{ Location = 'StartMenu'; Target = $ExeName; Conditional = $false }
        [pscustomobject]@{ Location = 'StartMenu'; Target = $UninstallName; Conditional = $false }
        [pscustomobject]@{ Location = 'Desktop'; Target = $ExeName; Conditional = $true }
      )
      $SystemEffects = [pscustomobject][ordered]@{
        RegistryWrites     = @($RegistryWrites)
        RegistryRoutes     = @($RegistryRoutes)
        Shortcuts          = $Shortcuts
        CreatesUpdater     = $true
        CreatesUninstaller = $true
        Protocols          = @($AssociationInfo.Protocols)
        FileExtensions     = @($AssociationInfo.FileExtensions)
        PathChanges        = @()
        AutorunEntries     = @()
        FirewallRules      = @()
        Certificates       = @()
      }

      return [pscustomobject][ordered]@{
        Path                           = $File.FullName
        Family                         = 'Kachina'
        InstallerType                  = 'Kachina'
        FormatGeneration               = $Context.FormatGeneration
        ProductCode                    = $ProductCode
        UpgradeCode                    = $null
        DisplayName                    = $DisplayName
        DisplayVersion                 = $DisplayVersion
        Publisher                      = $Publisher
        Scope                          = $Scope
        SupportedScopes                = $SupportedScopes
        DefaultScopeIsAuthoritative    = $true
        UacStrategy                    = $UacStrategy
        ElevationRequirement           = 'elevatesSelf'
        DefaultInstallLocation         = $DefaultInstallLocation
        InstallLocation                = $DefaultInstallLocation
        UninstallString                = $UninstallString
        QuietUninstallString           = $null
        DisplayIcon                    = $DisplayIcon
        SystemComponent                = $false
        RegistryView                   = $RegistryView
        WritesAppsAndFeaturesEntry     = $true
        AppsAndFeaturesProductCode     = $ProductCode
        AppsAndFeaturesInstallerType   = 'exe'
        AppsAndFeaturesEntries         = $AppsAndFeaturesEntries
        RegistryWrites                 = @($RegistryWrites)
        RegistryRoutes                 = @($RegistryRoutes)
        Configuration                  = $Config
        Metadata                       = $Metadata
        Source                         = $Source
        AppName                        = $DisplayName
        RegName                        = $ProductCode
        ExeName                        = $ExeName
        UninstallName                  = $UninstallName
        UpdaterName                    = $UpdaterName
        ProgramFilesPath               = $ProgramFilesPath
        OuterArchitectureInfo          = $OuterArchitectureInfo
        PayloadFiles                   = $Catalog
        PayloadArchitectures           = @($PayloadEvidence.Architectures)
        PayloadArchitectureInfo        = $PayloadEvidence.ArchitectureInfo
        DependencyInfo                 = $PayloadEvidence.DependencyInfo
        RecommendedPackageDependencies = $PayloadEvidence.DependencyInfo ? @($PayloadEvidence.DependencyInfo.RecommendedPackageDependencies) : @()
        ConfiguredRuntimes             = $ConfiguredRuntimes
        RuntimePackages                = $RuntimePackages
        EmbeddedRuntimePackages        = $EmbeddedRuntimePackages
        PatchFiles                     = $Patches
        EmbeddedRecords                = @($Context.Records | ForEach-Object { [pscustomobject]@{ Name = $_.DisplayName; RawOffset = $_.RawOffset; DataOffset = $_.DataOffset; Length = $_.Length } })
        PreIndex                       = $Context.PreIndex
        IndexEntries                   = $Context.Index
        GeneratedExecutableLength      = $Context.GeneratedExecutableEnd
        CanExpand                      = $CanExpand
        InstallModes                   = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches              = [ordered]@{ Silent = '-S'; SilentWithProgress = '-I'; InstallLocation = '-D "<INSTALLPATH>"' }
        SupportedCommandLineSwitches   = @('-D', '-I', '-S', '-O', '-U')
        Shortcuts                      = $Shortcuts
        SystemEffects                  = $SystemEffects
        Protocols                      = @($AssociationInfo.Protocols)
        FileExtensions                 = @($AssociationInfo.FileExtensions)
        ProtocolAssociations           = @($AssociationInfo.ProtocolAssociations)
        FileExtensionAssociations      = @($AssociationInfo.FileExtensionAssociations)
        RegistryAssociationInfo        = $AssociationInfo
        Notices                        = @($Notices)
        Warnings                       = @($Warnings)
        UnresolvedFields               = @($UnresolvedFields | Sort-Object -Unique)
        ParserVersionInfo              = [pscustomobject]@{ Name = 'Dumplings Kachina parser'; Version = 1; Generation = $Context.FormatGeneration; Evidence = @('PE overlay Kachina TLV stream', 'compiled JSON configuration', 'metadata/index cross-check') }
      }
    } finally { $Stream.Dispose() }
  }
}

function Test-KachinaInstaller {
  <#
  .SYNOPSIS
    Test whether a PE contains a structurally valid Kachina configuration and record stream.
  .PARAMETER Path
    Candidate installer path.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    try {
      $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force -ErrorAction Stop
      $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try { $null = Get-KachinaAnalysisContext -File $File -Stream $Stream; return $true } finally { $Stream.Dispose() }
    } catch { return $false }
  }
}

function Expand-KachinaInstaller {
  <#
  .SYNOPSIS
    Expand Kachina installed files or raw physical records without executing payloads.
  .PARAMETER Path
    Kachina installer path.
  .PARAMETER DestinationPath
    Output directory. A temporary directory is created when omitted.
  .PARAMETER Name
    Wildcard over installed relative paths. Omit it to expand all installed files.
  .PARAMETER RawEntries
    Export raw TLV content instead of decompressing installed files.
  .PARAMETER CollisionAction
    Existing or duplicate path behavior. Prompt asks only after a collision occurs.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit in bytes.
  .PARAMETER MaximumEntries
    Maximum selected output file count.
  .OUTPUTS
    FileInfo objects for expanded files.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [switch]$RawEntries,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184,
    [ValidateRange(1, 65536)][int]$MaximumEntries = $Script:KachinaMaximumRecords
  )

  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Context = Get-KachinaAnalysisContext -File $File -Stream $Stream
      $Files = [Collections.Generic.List[IO.FileInfo]]::new()
      $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $ExpandedBytes = 0L
      if ($RawEntries) {
        foreach ($Record in $Context.Records) {
          $SafeName = switch -CaseSensitive ($Record.Name) {
            "`0CONFIG" { 'config.json'; break }
            "`0IMAGE" { 'image.bin'; break }
            "`0INDEX" { 'index.bin'; break }
            "`0META" { 'metadata.json'; break }
            '.config.json' { 'config.json'; break }
            '.metadata.json' { 'metadata.json'; break }
            '.image' { 'image.bin'; break }
            default { ($Record.Name -replace '[\x00-\x1F<>:"/\\|?*]', '_') }
          }
          $RelativePath = Join-Path '_kachina\entries' $SafeName
          if (-not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name) -and -not (Test-ExtractionPattern -Path $Record.DisplayName -Pattern $Name)) { continue }
          if ($Files.Count -ge $MaximumEntries) { throw "The Kachina raw selection exceeds the $MaximumEntries-entry limit." }
          if ($Record.Length -gt $MaximumExpandedBytes - $ExpandedBytes) { throw "The Kachina raw selection exceeds the $MaximumExpandedBytes-byte output limit." }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $Parent = Split-Path -Parent $Target.Path
          $null = New-Item -Path $Parent -ItemType Directory -Force
          $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try { Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Record.DataOffset -Length $Record.Length } finally { $Output.Dispose() }
          $OutputFile = Get-Item -LiteralPath $Target.Path -Force
          $ExpandedBytes += $OutputFile.Length
          $Files.Add($OutputFile)
        }
        return @($Files)
      }

      if (-not $Context.Metadata) { throw 'The config-only Kachina updater does not embed an installed payload.' }
      $Warnings = [Collections.Generic.List[string]]::new()
      $Catalog = @(Get-KachinaPayloadCatalog -Context $Context -Warnings $Warnings)
      if ($Warnings.Count -gt 0) { throw $Warnings[0] }
      $Selection = Export-KachinaPayloadSelection -Context $Context -Catalog $Catalog -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries $MaximumEntries
      foreach ($OutputFile in $Selection.Files) { $Files.Add($OutputFile) }
      foreach ($OutputFile in $Files) { $null = $ReservedPaths.Add($OutputFile.FullName) }
      $ExpandedBytes = $Selection.ExpandedBytes
      foreach ($GeneratedName in @([string](Get-KachinaMapValue -Map $Context.Config -Name 'updaterName' -DefaultValue 'update.exe'), [string](Get-KachinaMapValue -Map $Context.Config -Name 'uninstallName' -DefaultValue 'uninst.exe'))) {
        if (-not (Test-ExtractionPattern -Path $GeneratedName -Pattern $Name)) { continue }
        if ($Files.Count -ge $MaximumEntries) { throw "The Kachina output exceeds the $MaximumEntries-entry limit." }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $GeneratedName -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        $RemainingBytes = $MaximumExpandedBytes - $ExpandedBytes
        if ($RemainingBytes -le 0) { throw "The Kachina output exceeds the $MaximumExpandedBytes-byte output limit." }
        $Generated = Export-KachinaGeneratedExecutable -Context $Context -DestinationPath $Target.Path -MaximumBytes $RemainingBytes
        $ExpandedBytes += $Generated.Length
        $Files.Add($Generated)
      }
      return @($Files)
    } finally { $Stream.Dispose() }
  }
}

function Read-ProductVersionFromKachina {
  <#
  .SYNOPSIS
    Read Kachina DisplayVersion metadata.
  .PARAMETER Path
    Kachina installer path.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-KachinaInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromKachina {
  <#
  .SYNOPSIS
    Read the Kachina application display name.
  .PARAMETER Path
    Kachina installer path.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-KachinaInfo -Path $Path).DisplayName }
}

function Read-PublisherFromKachina {
  <#
  .SYNOPSIS
    Read the Kachina publisher.
  .PARAMETER Path
    Kachina installer path.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-KachinaInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromKachina {
  <#
  .SYNOPSIS
    Read the Kachina uninstall key name.
  .PARAMETER Path
    Kachina installer path.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-KachinaInfo -Path $Path).ProductCode }
}

function Read-ScopeFromKachina {
  <#
  .SYNOPSIS
    Read the default Kachina scope.
  .PARAMETER Path
    Kachina installer path.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-KachinaInfo -Path $Path).Scope }
}

function Read-ProtocolsFromKachina {
  <#
  .SYNOPSIS
    Read literal protocol associations proven by Kachina records.
  .PARAMETER Path
    Kachina installer path.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return @((Get-KachinaInfo -Path $Path).Protocols) }
}

function Read-FileExtensionsFromKachina {
  <#
  .SYNOPSIS
    Read literal file-extension associations proven by Kachina records.
  .PARAMETER Path
    Kachina installer path.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return @((Get-KachinaInfo -Path $Path).FileExtensions) }
}

Export-ModuleMember -Function Get-KachinaInfo, Test-KachinaInstaller, Expand-KachinaInstaller, Read-ProductVersionFromKachina, Read-ProductNameFromKachina, Read-PublisherFromKachina, Read-ProductCodeFromKachina, Read-ScopeFromKachina, Read-ProtocolsFromKachina, Read-FileExtensionsFromKachina
