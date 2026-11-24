# SPDX-License-Identifier: Apache-2.0
# Internal DeployMaster implementation. See DeployMaster.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# DeployMaster classic implementation, imported locally by the public facade.
Import-Module (Join-Path $PSScriptRoot 'DeployMasterModern.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Test-DeployMasterClassicZlibHeader {
  <#
  .SYNOPSIS
    Test the two-byte RFC 1950 header used by a classic DeployMaster record.
  .PARAMETER Bytes
    Exactly two bytes beginning at the compressed-data boundary.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][ValidateCount(2, 2)][byte[]]$Bytes)

  # Classic media uses Deflate with a 32 KiB window and no preset dictionary. Checking FCHECK
  # avoids treating arbitrary 0x78 bytes inside compressed payloads as record boundaries.
  return $Bytes[0] -eq 0x78 -and (([int]$Bytes[0] * 256 + $Bytes[1]) % 31) -eq 0 -and ($Bytes[1] -band 0x20) -eq 0
}

function Get-DeployMasterClassicLogicalEndCandidate {
  <#
  .SYNOPSIS
    Return physical or pre-certificate offsets at which the classic record stream may end.
  .PARAMETER Stream
    Caller-owned seekable installer stream. The function does not dispose it.
  .PARAMETER PELayout
    Parsed PE layout used to separate an Authenticode certificate table from the installer data.
  #>
  [OutputType([long[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$PELayout
  )

  $Candidates = [Collections.Generic.List[long]]::new()
  $Candidates.Add($Stream.Length)
  $Certificate = $PELayout.DataDirectories['Certificate']
  if ($Certificate -and [long]$Certificate.Offset -gt 0 -and [long]$Certificate.Size -gt 0 -and
    [long]$Certificate.Offset + [long]$Certificate.Size -eq $Stream.Length) {
    $CertificateOffset = [long]$Certificate.Offset
    # Authenticode starts on an eight-byte boundary. Try every all-zero alignment suffix because
    # classic media does not carry the modern locator's explicit logical file length.
    for ($PaddingLength = 0; $PaddingLength -le 7; $PaddingLength++) {
      $LogicalEnd = $CertificateOffset - $PaddingLength
      if ($LogicalEnd -le 0) { continue }
      if ($PaddingLength) {
        $Padding = Read-BinaryBytes -Stream $Stream -Offset $LogicalEnd -Count $PaddingLength
        if ($Padding | Where-Object { $_ -ne 0 } | Select-Object -First 1) { continue }
      }
      if (-not $Candidates.Contains($LogicalEnd)) { $Candidates.Add($LogicalEnd) }
    }
  }
  return $Candidates.ToArray()
}

function Get-DeployMasterClassicRuntimeRecord {
  <#
  .SYNOPSIS
    Locate and validate the BZip2-compressed runtime at the start of a classic overlay.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER OverlayOffset
    Absolute offset of the BZip2 member.
  .PARAMETER MaximumEndOffset
    Exclusive upper bound for the package data, excluding any certificate table.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted expanded runtime size.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$OverlayOffset,
    [Parameter(Mandatory)][long]$MaximumEndOffset,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 67108864
  )

  $ScanLength = [Math]::Min($MaximumEndOffset - $OverlayOffset - 4, 268435456L)
  if ($ScanLength -le 0) { throw 'The classic DeployMaster BZip2 runtime is truncated.' }
  # A random compressed stream should contain very few four-byte all-ones runs. Keep candidate
  # decompression bounded as well as byte scanning so a hostile file cannot force thousands of
  # full BZip2 probes before parser rejection.
  $Markers = @(Find-BinaryPattern -Stream $Stream -Pattern ([byte[]](0xFF, 0xFF, 0xFF, 0xFF)) -StartOffset ($OverlayOffset + 4) -Length $ScanLength -Maximum 65)
  if ($Markers.Count -gt 64) { throw 'The classic DeployMaster runtime contains too many candidate end markers.' }

  foreach ($MarkerOffset in $Markers) {
    # The marker is accepted only when the following bytes begin a bounded length-prefixed zlib
    # record and the preceding BZip2 member expands to a valid PE runtime.
    if ($MarkerOffset + 10 -gt $MaximumEndOffset) { continue }
    $FirstRecordLength = [long](Read-BinaryInteger -Stream $Stream -Offset ($MarkerOffset + 4) -Size 4)
    if ($FirstRecordLength -lt 6 -or $FirstRecordLength -gt $MaximumEndOffset - ($MarkerOffset + 8)) { continue }
    $ZlibHeader = Read-BinaryBytes -Stream $Stream -Offset ($MarkerOffset + 8) -Count 2
    if (-not (Test-DeployMasterClassicZlibHeader -Bytes $ZlibHeader)) { continue }

    $CompressedSize = $MarkerOffset - $OverlayOffset
    $InputStream = New-BoundedReadStream -Stream $Stream -Offset $OverlayOffset -Length $CompressedSize -LeaveOpen
    $Output = [IO.MemoryStream]::new()
    try {
      try { $ExpandedSize = Expand-InstallerCompressedStream -Algorithm BZip2 -Stream $InputStream -Destination $Output -MaximumBytes $MaximumExpandedBytes }
      catch { continue }
      $Output.Position = 0
      try { $RuntimeLayout = Get-PELayout -Stream $Output }
      catch { continue }
      return [pscustomobject]@{
        Offset           = $OverlayOffset
        CompressedSize   = $CompressedSize
        UncompressedSize = [long]$ExpandedSize
        EndOffset        = [long]$MarkerOffset
        MarkerOffset     = [long]$MarkerOffset
        Compression      = 'BZip2'
        Architecture     = switch ($RuntimeLayout.MachineName) { 'I386' { 'x86' } 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { $null } }
        MachineName      = $RuntimeLayout.MachineName
      }
    } finally {
      $Output.Dispose()
      $InputStream.Dispose()
    }
  }
  throw 'The classic DeployMaster BZip2 runtime does not have a validated end marker.'
}

function Get-DeployMasterClassicZlibRecord {
  <#
  .SYNOPSIS
    Index candidate classic length-prefixed zlib records without expanding their payloads.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER StartOffset
    Absolute beginning of the record search.
  .PARAMETER EndOffset
    Exclusive absolute package boundary.
  .PARAMETER MaximumRecordCount
    Maximum accepted number of structurally valid candidates.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$StartOffset,
    [Parameter(Mandatory)][long]$EndOffset,
    [ValidateRange(1, 1048576)][int]$MaximumRecordCount = 131072
  )

  if ($StartOffset -lt 0 -or $EndOffset -le $StartOffset -or $EndOffset -gt $Stream.Length) { throw 'The classic DeployMaster zlib search range is invalid.' }
  $ByOffset = [Collections.Generic.Dictionary[long, object]]::new()
  foreach ($Header in [byte[]](0x78, 0x01), [byte[]](0x78, 0x5E), [byte[]](0x78, 0x9C), [byte[]](0x78, 0xDA)) {
    $PatternOffsets = @(Find-BinaryPattern -Stream $Stream -Pattern $Header -StartOffset $StartOffset -Length ($EndOffset - $StartOffset) -Maximum ($MaximumRecordCount + 1))
    if ($PatternOffsets.Count -gt $MaximumRecordCount) { throw 'The classic DeployMaster package exceeds the zlib candidate limit.' }
    foreach ($DataOffset in $PatternOffsets) {
      $RecordOffset = [long]$DataOffset - 4
      if ($RecordOffset -lt $StartOffset) { continue }
      $CompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset $RecordOffset -Size 4)
      if ($CompressedSize -lt 6 -or $CompressedSize -gt $EndOffset - [long]$DataOffset) { continue }
      $RecordEnd = [long]$DataOffset + $CompressedSize
      if (-not $ByOffset.ContainsKey($RecordOffset)) {
        $ByOffset.Add($RecordOffset, [pscustomobject]@{
            Offset           = $RecordOffset
            DataOffset       = [long]$DataOffset
            CompressedSize   = $CompressedSize
            UncompressedSize = $null
            EndOffset        = $RecordEnd
            Compression      = 'Zlib'
          })
        if ($ByOffset.Count -gt $MaximumRecordCount) { throw 'The classic DeployMaster package exceeds the zlib record limit.' }
      }
    }
  }
  return [object[]]@($ByOffset.Values | Sort-Object Offset)
}

function Read-DeployMasterClassicZlibRecordData {
  <#
  .SYNOPSIS
    Expand one validated classic zlib record into a bounded byte array.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Record
    Record returned by Get-DeployMasterClassicZlibRecord.
  .PARAMETER MaximumBytes
    Maximum expanded byte count.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Record,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes = 4194304
  )

  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Record.DataOffset -Length $Record.CompressedSize -LeaveOpen
  $Output = [IO.MemoryStream]::new()
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $InputStream -Destination $Output -MaximumBytes $MaximumBytes -CompressedSize $Record.CompressedSize
    return $Output.ToArray()
  } finally {
    $Output.Dispose()
    $InputStream.Dispose()
  }
}

function ConvertFrom-DeployMasterClassicFileNameBlock {
  <#
  .SYNOPSIS
    Validate a classic CRLF-delimited payload-name block.
  .PARAMETER Bytes
    Expanded candidate metadata bytes.
  .PARAMETER ExpectedCount
    Number of trailing payload records that the name block must describe.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(1, 65536)][int]$ExpectedCount
  )

  $Text = [Text.Encoding]::GetEncoding(1252).GetString($Bytes).TrimEnd([char[]]@([char]0, [char]13, [char]10))
  $Names = [regex]::Split($Text, '\r\n|\n|\r')
  if ($Names.Count -ne $ExpectedCount) { return }
  foreach ($Name in $Names) {
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 1024 -or $Name.IndexOf([char]0) -ge 0 -or
      [IO.Path]::IsPathRooted($Name) -or $Name -match '^[A-Za-z]:' -or
      @($Name -split '[\\/]' | Where-Object { $_ -in '.', '..' }).Count) { return }
  }
  return [pscustomobject]@{ Names = [string[]]$Names; Bytes = $Bytes }
}

function Find-DeployMasterClassicPayloadCatalog {
  <#
  .SYNOPSIS
    Match a trailing contiguous zlib chain with its nearest validated filename catalog.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Record
    All indexed classic zlib record candidates.
  .PARAMETER LogicalEndCandidate
    Candidate physical ends before any Authenticode table.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][long[]]$LogicalEndCandidate
  )

  $ByEnd = @{}
  foreach ($Candidate in $Record) {
    $Key = ([long]$Candidate.EndOffset).ToString([Globalization.CultureInfo]::InvariantCulture)
    if (-not $ByEnd.ContainsKey($Key)) { $ByEnd[$Key] = [Collections.Generic.List[object]]::new() }
    $ByEnd[$Key].Add($Candidate)
  }

  $Chains = [Collections.Generic.List[object]]::new()
  foreach ($LogicalEnd in $LogicalEndCandidate) {
    $ReverseRecords = [Collections.Generic.List[object]]::new()
    $Cursor = [long]$LogicalEnd
    while ($ReverseRecords.Count -lt 65536) {
      $Key = $Cursor.ToString([Globalization.CultureInfo]::InvariantCulture)
      if (-not $ByEnd.ContainsKey($Key)) { break }
      $Candidate = $ByEnd[$Key] | Sort-Object Offset -Descending | Select-Object -First 1
      $ReverseRecords.Add($Candidate)
      $Cursor = [long]$Candidate.Offset
    }
    if ($ReverseRecords.Count) {
      $Records = $ReverseRecords.ToArray()
      [Array]::Reverse($Records)
      $Chains.Add([pscustomobject]@{ LogicalEnd = [long]$LogicalEnd; Records = [object[]]$Records })
    }
  }

  foreach ($Chain in @($Chains | Sort-Object { $_.Records.Count } -Descending)) {
    $PayloadStart = [long]$Chain.Records[0].Offset
    # The filename catalog is close to, but not necessarily adjacent to, the first payload. Decode
    # only small metadata candidates and require an exact one-name-per-record match.
    foreach ($Candidate in @($Record | Where-Object {
          $_.EndOffset -le $PayloadStart -and $PayloadStart - $_.EndOffset -le 4194304 -and $_.CompressedSize -le 1048576
        } | Sort-Object Offset -Descending)) {
      try { $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes 4194304 }
      catch { continue }
      $Catalog = ConvertFrom-DeployMasterClassicFileNameBlock -Bytes $Bytes -ExpectedCount $Chain.Records.Count
      if ($Catalog) {
        return [pscustomobject]@{
          LogicalEnd     = $Chain.LogicalEnd
          Records        = $Chain.Records
          FileNameRecord = $Candidate
          FileNameBytes  = $Catalog.Bytes
          FileNames      = $Catalog.Names
        }
      }
    }
  }
  throw 'The classic DeployMaster trailing payload records do not have a matching filename catalog.'
}

function Complete-DeployMasterClassicFileCatalog {
  <#
  .SYNOPSIS
    Reconstruct the complete classic file-index namespace around the ordinary trailing payload chain.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access helpers restore its position.
  .PARAMETER Record
    All validated classic zlib records in the logical package.
  .PARAMETER Catalog
    Ordinary trailing payload chain and its matching filename record.
  .PARAMETER Identity
    Parsed classic identity containing the four possible auxiliary payload names.
  .PARAMETER IdentityEnd
    Absolute first byte after the classic identity record; auxiliary payload candidates begin here.
  .OUTPUTS
    The input catalog augmented with auxiliary records, complete names, expanded sizes, CRC32 values,
    preserved catalog-tail bytes, and the first structurally proven destination root when present.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][psobject]$Catalog,
    [Parameter(Mandatory)][psobject]$Identity,
    [Parameter(Mandatory)][long]$IdentityEnd
  )

  $OrdinaryRecords = @($Catalog.Records)
  $BehaviorStart = @($Record | Where-Object { $_.Offset -gt $Catalog.FileNameRecord.EndOffset -and $_.Offset -lt $OrdinaryRecords[0].Offset } | Sort-Object Offset | Select-Object -First 1)
  if ($BehaviorStart.Count -ne 1) { throw 'The classic DeployMaster file catalog does not have a bounded behavior-record boundary.' }
  $CatalogOffset = [long]$Catalog.FileNameRecord.EndOffset
  $CatalogLength = [long]$BehaviorStart[0].Offset - $CatalogOffset
  if ($CatalogLength -le 0 -or $CatalogLength -gt 1048576 -or $CatalogLength -gt [int]::MaxValue) { throw 'The classic DeployMaster file catalog is outside the configured bounds.' }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $CatalogOffset -Count ([int]$CatalogLength)

  # Classic catalogs reserve one 0xFFFFFFFF offset for each auxiliary payload physically stored
  # before the table. The remaining offsets must match the trailing zlib chain exactly.
  $AuxiliaryCount = 0
  while ($AuxiliaryCount -lt 4 -and 4 * ($AuxiliaryCount + 1) -le $Bytes.Length -and [BitConverter]::ToUInt32($Bytes, 4 * $AuxiliaryCount) -eq [uint32]::MaxValue) { $AuxiliaryCount++ }
  $EntryCount = $AuxiliaryCount + $OrdinaryRecords.Count
  if ($EntryCount -le 0 -or 24 * $EntryCount -gt $Bytes.Length) { throw 'The classic DeployMaster file catalog is truncated.' }
  for ($Index = 0; $Index -lt $OrdinaryRecords.Count; $Index++) {
    $SerializedOffset = [uint32][BitConverter]::ToUInt32($Bytes, 4 * ($AuxiliaryCount + $Index))
    if ($SerializedOffset -ne [uint32]$OrdinaryRecords[$Index].Offset) { throw 'The classic DeployMaster file catalog offsets do not match the payload chain.' }
  }

  $AuxiliaryNames = @(
    $Identity.DisplayIconFileName
    $Identity.ReadmeFileName
    $Identity.LicenseFileName
    $Identity.SupportDll32FileName
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
  if ($AuxiliaryNames.Count -ne $AuxiliaryCount) { throw 'The classic DeployMaster auxiliary file names do not match the file catalog.' }

  $ExpandedSizes = [Collections.Generic.List[long]]::new($EntryCount)
  $Crc32Values = [Collections.Generic.List[uint32]]::new($EntryCount)
  for ($Index = 0; $Index -lt $EntryCount; $Index++) {
    $ExpandedSize = [uint32][BitConverter]::ToUInt32($Bytes, (16 * $EntryCount) + (4 * $Index))
    if ($ExpandedSize -eq 0) { throw 'The classic DeployMaster file catalog contains an empty expanded-size entry.' }
    $ExpandedSizes.Add([long]$ExpandedSize)
    $Crc32Values.Add([uint32][BitConverter]::ToUInt32($Bytes, (20 * $EntryCount) + (4 * $Index)))
  }

  # Locate auxiliary payloads by the expanded-size and CRC columns. UI/configuration records can
  # occur in the same pre-catalog range, so neither record position nor apparent file magic alone
  # is sufficient evidence. Each auxiliary record must match exactly once and in catalog order.
  $PreCatalogRecords = @($Record | Where-Object { $_.Offset -ge $IdentityEnd -and $_.EndOffset -le $Catalog.FileNameRecord.Offset } | Sort-Object Offset)
  $DecodedCandidates = [Collections.Generic.List[object]]::new()
  $MaximumCandidateBytes = [Math]::Max(1L, ($ExpandedSizes | Measure-Object -Maximum).Maximum)
  foreach ($Candidate in $PreCatalogRecords) {
    if ($Candidate.CompressedSize -gt 134217728) { continue }
    try {
      $CandidateBytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes $MaximumCandidateBytes
      $DecodedCandidates.Add([pscustomobject]@{ Record = $Candidate; ExpandedSize = [long]$CandidateBytes.Length; Crc32 = [uint32](Get-BinaryCrc32 -Bytes $CandidateBytes) })
    } catch { continue }
  }
  $AuxiliaryRecords = [Collections.Generic.List[object]]::new($AuxiliaryCount)
  $PreviousOffset = -1L
  for ($Index = 0; $Index -lt $AuxiliaryCount; $Index++) {
    $CandidateMatches = @($DecodedCandidates | Where-Object { $_.Record.Offset -gt $PreviousOffset -and $_.ExpandedSize -eq $ExpandedSizes[$Index] -and $_.Crc32 -eq $Crc32Values[$Index] })
    if ($CandidateMatches.Count -ne 1) { throw "The classic DeployMaster auxiliary file at index $Index could not be located unambiguously." }
    $AuxiliaryRecords.Add($CandidateMatches[0].Record)
    $PreviousOffset = [long]$CandidateMatches[0].Record.Offset
  }

  $AllRecords = [Collections.Generic.List[object]]::new($EntryCount)
  foreach ($Candidate in $AuxiliaryRecords) { $AllRecords.Add($Candidate) }
  foreach ($Candidate in $OrdinaryRecords) { $AllRecords.Add($Candidate) }
  $AllNames = [Collections.Generic.List[string]]::new($EntryCount)
  foreach ($Name in $AuxiliaryNames) { $AllNames.Add([string]$Name) }
  foreach ($Name in $Catalog.FileNames) { $AllNames.Add([string]$Name) }

  $DestinationRoot = ConvertFrom-DeployMasterClassicDestinationTail -Bytes $(
    if (24 * $EntryCount -lt $Bytes.Length) { [byte[]]$Bytes[(24 * $EntryCount)..($Bytes.Length - 1)] }
    else { [byte[]]::new(0) }
  )
  return [pscustomobject]@{
    LogicalEnd        = $Catalog.LogicalEnd
    Records           = $OrdinaryRecords
    FileNameRecord    = $Catalog.FileNameRecord
    FileNameBytes     = $Catalog.FileNameBytes
    FileNames         = $Catalog.FileNames
    AuxiliaryCount    = $AuxiliaryCount
    AuxiliaryRecords  = $AuxiliaryRecords.ToArray()
    AllRecords        = $AllRecords.ToArray()
    AllFileNames      = $AllNames.ToArray()
    ExpandedSizes     = $ExpandedSizes.ToArray()
    Crc32Values       = $Crc32Values.ToArray()
    CatalogOffset     = $CatalogOffset
    CatalogLength     = $CatalogLength
    InstallTreeOffset = $CatalogOffset + (24 * $EntryCount)
    ObservedTailBytes = if (24 * $EntryCount -lt $Bytes.Length) { $Bytes[(24 * $EntryCount)..($Bytes.Length - 1)] } else { [byte[]]::new(0) }
    DestinationRoot   = $DestinationRoot
  }
}

function ConvertFrom-DeployMasterClassicDestinationTail {
  <#
  .SYNOPSIS
    Decode the classic catalog suffix that introduces the first installation-item destination.
  .PARAMETER Bytes
    Catalog-relative bytes after the six parallel file-entry columns. The caller retains ownership
    of the array.
  .OUTPUTS
    A folder record when the complete suffix is one bounded Windows-1252 name followed by the
    classic 0xFE item-list marker; otherwise no output.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  # Archived 2.5.3 media emits [Length:u8][Name:Windows-1252][0xFE]. Do not consume a prefix of a
  # richer unknown tail: exact length and terminator checks keep later classic variants unresolved.
  if ($Bytes.Length -lt 3 -or $Bytes[-1] -ne 0xFE) { return }
  $Length = [int]$Bytes[0]
  if ($Length -lt 1 -or $Length + 2 -ne $Bytes.Length) { return }
  $Name = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, 1, $Length)
  if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0 -or $Name -match '[\x00-\x1F]') { return }
  return [pscustomobject]@{
    ComponentIndex = $null
    Name           = $Name
    FullName       = $Name
    CreateIfEmpty  = $false
    Evidence       = 'Classic catalog destination name followed by the 0xFE item-list marker'
  }
}

function ConvertFrom-DeployMasterClassicComponentBlock {
  <#
  .SYNOPSIS
    Decode one classic DeployMaster component descriptor.
  .PARAMETER Bytes
    Expanded component record using byte-sized flags, name length, and requirement indexes followed
    by a Windows-1252 description.
  .PARAMETER ComponentIndex
    Zero-based record-order index used to validate that requirements reference earlier components.
  .OUTPUTS
    A normalized component record, or no output when the byte sequence is not a complete component.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, 255)][int]$ComponentIndex
  )

  if ($Bytes.Length -lt 4 -or $Bytes[0] -notin 1, 3) { return }
  $Flags = [int]$Bytes[0]
  $NameLength = [int]$Bytes[1]
  if ($NameLength -lt 1 -or 3 + $NameLength -gt $Bytes.Length) { return }
  $Name = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, 2, $NameLength)
  if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0 -or $Name -match '[\x00-\x1F]') { return }
  $Cursor = 2 + $NameLength
  $RequirementCount = [int]$Bytes[$Cursor++]
  if ($RequirementCount -gt $ComponentIndex -or $Cursor + $RequirementCount -gt $Bytes.Length) { return }
  $Requirements = [Collections.Generic.List[int]]::new($RequirementCount)
  for ($Index = 0; $Index -lt $RequirementCount; $Index++) {
    $Requirement = [int]$Bytes[$Cursor++]
    if ($Requirement -ge $ComponentIndex -or $Requirements.Contains($Requirement)) { return }
    $Requirements.Add($Requirement)
  }
  $Description = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Cursor, $Bytes.Length - $Cursor).TrimEnd([char]0)
  if ($Description.IndexOf([char]0) -ge 0) { return }
  return [pscustomobject]@{
    Index              = $ComponentIndex
    Name               = $Name
    Flags              = $Flags
    InstalledByDefault = [bool]($Flags -band 0x01)
    UserSelectable     = [bool]($Flags -band 0x02)
    Requirements       = $Requirements.ToArray()
    Description        = $Description
  }
}

function Read-DeployMasterClassicComponentCatalog {
  <#
  .SYNOPSIS
    Locate classic component descriptors between the identity and filename catalog records.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its position.
  .PARAMETER Record
    All indexed classic zlib records in the logical package.
  .PARAMETER Catalog
    Completed classic file catalog, used to exclude auxiliary payload records and bound the scan.
  .PARAMETER IdentityEnd
    Absolute first byte after the identity record.
  .OUTPUTS
    Ordered component descriptors and the zlib records that supplied them.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][psobject]$Catalog,
    [Parameter(Mandatory)][long]$IdentityEnd
  )

  $AuxiliaryOffsets = [Collections.Generic.HashSet[long]]::new()
  foreach ($AuxiliaryRecord in @($Catalog.AuxiliaryRecords)) { $null = $AuxiliaryOffsets.Add([long]$AuxiliaryRecord.Offset) }
  $Components = [Collections.Generic.List[object]]::new()
  $ComponentRecords = [Collections.Generic.List[object]]::new()
  foreach ($Candidate in @($Record | Where-Object {
        $_.Offset -ge $IdentityEnd -and $_.EndOffset -le $Catalog.FileNameRecord.Offset -and
        -not $AuxiliaryOffsets.Contains([long]$_.Offset) -and $_.CompressedSize -le 1048576
      } | Sort-Object Offset)) {
    try { $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes 1048576 }
    catch { continue }
    $Component = ConvertFrom-DeployMasterClassicComponentBlock -Bytes $Bytes -ComponentIndex $Components.Count
    if (-not $Component) { continue }
    $Components.Add($Component)
    $ComponentRecords.Add($Candidate)
  }
  return [pscustomobject]@{
    Components       = $Components.ToArray()
    ComponentRecords = $ComponentRecords.ToArray()
  }
}

function ConvertFrom-DeployMasterClassicIdentity {
  <#
  .SYNOPSIS
    Decode the Windows-1252 form-feed identity record used by DeployMaster 2.x.
  .PARAMETER Bytes
    Expanded classic identity bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $Text = [Text.Encoding]::GetEncoding(1252).GetString($Bytes).TrimEnd([char]0)
  $Fields = $Text.Split([char]12)
  if ($Fields.Count -lt 17 -or [string]::IsNullOrWhiteSpace($Fields[2]) -or [string]::IsNullOrWhiteSpace($Fields[4])) {
    throw 'The classic DeployMaster identity record is incomplete.'
  }
  $ReleaseDate = $null
  $ReleaseDateValue = 0.0
  if ([double]::TryParse($Fields[5], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ReleaseDateValue)) {
    try { $ReleaseDate = [datetime]::FromOADate($ReleaseDateValue).Date } catch {}
  }
  $RawMachineInstallLocation = [string]$Fields[11]
  $RawUserInstallLocation = [string]$Fields[12]
  $RawMachineMenuLocation = [string]$Fields[13]
  $RawUserMenuLocation = [string]$Fields[14]
  return [pscustomobject]@{
    Publisher                 = $Fields[0]
    PublisherUrl              = $Fields[1]
    DisplayName               = $Fields[2]
    PackageUrl                = $Fields[3]
    DisplayVersion            = $Fields[4]
    ReleaseDateValue          = $Fields[5]
    ReleaseDate               = $ReleaseDate
    Copyright                 = $Fields[6]
    DisplayIconFileName       = $Fields[7]
    ReadmeFileName            = $Fields[8]
    LicenseFileName           = $Fields[9]
    SupportDll32FileName      = $Fields[10]
    MachineInstallLocation    = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineInstallLocation
    UserInstallLocation       = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserInstallLocation
    RawMachineInstallLocation = $RawMachineInstallLocation
    RawUserInstallLocation    = $RawUserInstallLocation
    MachineMenuLocation       = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineMenuLocation
    UserMenuLocation          = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserMenuLocation
    RawMachineMenuLocation    = $RawMachineMenuLocation
    RawUserMenuLocation       = $RawUserMenuLocation
    Description               = $Fields[15]
    AdditionalText            = $Fields[16]
    Fields                    = [string[]]$Fields
  }
}

function ConvertFrom-DeployMasterClassicInstallItemBlock {
  <#
  .SYNOPSIS
    Decode one flat classic file, shortcut, and URL-shortcut item stream.
  .PARAMETER Bytes
    Expanded zlib record. The record must be consumed exactly.
  .PARAMETER FileEntries
    Complete classic file catalog, including auxiliary entries at indexes zero through three.
  .PARAMETER GroupIndex
    Stable record-order index within the complete installation tree.
  .PARAMETER Directory
    Folder-tree destination that owns this item block.
  .PARAMETER ComponentIndex
    Zero-based component whose folder tree contains this item block.
  .OUTPUTS
    Installed files, file shortcuts, and URL shortcuts with their decoded destination and component.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][ValidateRange(0, 65535)][int]$GroupIndex,
    [AllowNull()][string]$Directory,
    [AllowNull()][Nullable[int]]$ComponentIndex
  )

  if ($Bytes.Length -eq 0 -or ($Bytes[0] -band 0xF0) -notin 0x20, 0x40, 0x80) { return }
  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Files = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $UrlShortcuts = [Collections.Generic.List[object]]::new()

  function Read-DeployMasterClassicItemString {
    $Length = [int](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    if ($Stream.Position + $Length -gt $Stream.Length) { throw 'The classic DeployMaster item string is truncated.' }
    if ($Length -eq 0) { return '' }
    $ValueBytes = [byte[]]::new($Length)
    if ($Stream.Read($ValueBytes, 0, $Length) -ne $Length) { throw 'The classic DeployMaster item string is truncated.' }
    return [Text.Encoding]::GetEncoding(1252).GetString($ValueBytes)
  }

  try {
    while ($Stream.Position -lt $Stream.Length) {
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      switch ($Opcode -band 0xF0) {
        0x80 {
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The classic DeployMaster file item index is outside the file catalog.' }
          $Entry = $FileEntries[$FileIndex]
          $ActionCode = [int]($Opcode -band 0x0F)
          $DestinationPath = if ([string]::IsNullOrWhiteSpace($Directory)) { $Entry.Name } else { "$Directory\$($Entry.Name)" }
          $Files.Add([pscustomobject]@{
              GroupIndex        = $GroupIndex
              ComponentIndex    = $ComponentIndex
              DestinationPath   = $DestinationPath
              Directory         = $Directory
              FileIndex         = $FileIndex
              SourceName        = $Entry.Name
              Included          = $true
              Architectures     = @('x86')
              FileAction        = $ActionCode
              OverwriteBehavior = switch ($ActionCode) { 0 { 'AlwaysOverwrite' } 1 { 'OverwriteIfNewer' } default { 'Unknown' } }
              NeverUninstall    = $false
              OpcodeFlags       = $ActionCode
              Flags             = $null
              OptionalArgument  = $null
            })
        }
        0x40 {
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The classic DeployMaster shortcut file index is outside the file catalog.' }
          $Values = @(Read-DeployMasterClassicItemString; Read-DeployMasterClassicItemString; Read-DeployMasterClassicItemString)
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $Shortcuts.Add([pscustomobject]@{
              GroupIndex = $GroupIndex; ComponentIndex = $ComponentIndex; Directory = $Directory; TargetFileIndex = $FileIndex
              TargetFile = $FileEntries[$FileIndex].Name; Values = $Values; Flags = $Flags
              Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 0x0F)
            })
        }
        0x20 {
          $Url = Read-DeployMasterClassicItemString
          $Name = Read-DeployMasterClassicItemString
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $UrlShortcuts.Add([pscustomobject]@{
              GroupIndex = $GroupIndex; ComponentIndex = $ComponentIndex; Directory = $Directory; Name = $Name; Url = $Url
              Flags = $Flags; Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 0x0F)
            })
        }
        default { throw "Unsupported classic DeployMaster item opcode 0x$($Opcode.ToString('X2'))." }
      }
    }
  } finally { $Stream.Dispose() }

  return [pscustomobject]@{
    GroupIndex     = $GroupIndex
    ComponentIndex = $ComponentIndex
    Directory      = $Directory
    Files          = $Files.ToArray()
    Shortcuts      = $Shortcuts.ToArray()
    UrlShortcuts   = $UrlShortcuts.ToArray()
  }
}

function Read-DeployMasterClassicInstallTreeNodeList {
  <#
  .SYNOPSIS
    Decode one recursive folder-node list from a classic DeployMaster installation tree.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its position.
  .PARAMETER Cursor
    Reference to the absolute next unread byte. The function advances it past one node list.
  .PARAMETER EndOffset
    Exclusive absolute boundary of the classic behavior region.
  .PARAMETER RecordByOffset
    Validated zlib records keyed by their absolute record offset.
  .PARAMETER FileEntries
    Complete classic file-index namespace.
  .PARAMETER ComponentIndex
    Zero-based component that owns this root tree.
  .PARAMETER Directory
    Parent destination. Root node names are DeployMaster variables; nested names append to this path.
  .PARAMETER ResolveRootVariable
    Treat child names as root destination expressions rather than relative folder names.
  .PARAMETER GroupIndex
    Reference to the next stable item-group index.
  .PARAMETER Groups
    Output collection for decoded item groups.
  .PARAMETER Folders
    Output collection for decoded destination folders.
  .PARAMETER InstalledFiles
    Output collection for installed-file items.
  .PARAMETER Shortcuts
    Output collection for file shortcuts.
  .PARAMETER UrlShortcuts
    Output collection for URL shortcuts.
  .PARAMETER ItemRecords
    Output collection for zlib records consumed by 0xFE item markers.
  .PARAMETER Depth
    Current recursion depth, bounded to reject malformed trees.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ref]$Cursor,
    [Parameter(Mandatory)][long]$EndOffset,
    [Parameter(Mandatory)][hashtable]$RecordByOffset,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [AllowNull()][Nullable[int]]$ComponentIndex,
    [AllowNull()][string]$Directory,
    [switch]$ResolveRootVariable,
    [Parameter(Mandatory)][ref]$GroupIndex,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Groups,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Folders,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$InstalledFiles,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Shortcuts,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$UrlShortcuts,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$ItemRecords,
    [ValidateRange(0, 64)][int]$Depth = 0
  )

  if ($Depth -ge 64) { throw 'The classic DeployMaster installation tree exceeds the recursion limit.' }
  while ([long]$Cursor.Value -lt $EndOffset) {
    $Opcode = [byte](Read-BinaryInteger -Stream $Stream -Offset ([long]$Cursor.Value) -Size 1)
    $Cursor.Value = [long]$Cursor.Value + 1

    # 0xFF closes the current folder list. 0xFE attaches one compressed item stream to the
    # current directory and then closes the list, matching the classic runtime reader.
    if ($Opcode -eq 0xFF) { return }
    if ($Opcode -eq 0xFE) {
      $RecordKey = ([long]$Cursor.Value).ToString([Globalization.CultureInfo]::InvariantCulture)
      if (-not $RecordByOffset.ContainsKey($RecordKey)) { throw 'The classic DeployMaster installation tree points to an invalid item record.' }
      $Record = $RecordByOffset[$RecordKey]
      $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Record -MaximumBytes 4194304
      $Group = ConvertFrom-DeployMasterClassicInstallItemBlock -Bytes $Bytes -FileEntries $FileEntries -GroupIndex ([int]$GroupIndex.Value) -Directory $Directory -ComponentIndex $ComponentIndex
      if (-not $Group) { throw 'The classic DeployMaster installation tree contains an invalid item block.' }
      $Groups.Add($Group)
      foreach ($Item in @($Group.Files)) { $InstalledFiles.Add($Item) }
      foreach ($Item in @($Group.Shortcuts)) { $Shortcuts.Add($Item) }
      foreach ($Item in @($Group.UrlShortcuts)) { $UrlShortcuts.Add($Item) }
      $ItemRecords.Add($Record)
      $GroupIndex.Value = [int]$GroupIndex.Value + 1
      $Cursor.Value = [long]$Record.EndOffset
      return
    }

    # Values below 0xFE are byte-sized Windows-1252 folder-name lengths. The root call resolves
    # names such as %APPFOLDER%; recursive calls append ordinary subdirectory names.
    $NameLength = [int]$Opcode
    if ([long]$Cursor.Value + $NameLength -gt $EndOffset) { throw 'The classic DeployMaster installation folder name is truncated.' }
    $NameBytes = if ($NameLength) { Read-BinaryBytes -Stream $Stream -Offset ([long]$Cursor.Value) -Count $NameLength } else { [byte[]]::new(0) }
    $Cursor.Value = [long]$Cursor.Value + $NameLength
    $Name = [Text.Encoding]::GetEncoding(1252).GetString($NameBytes)
    if ($Name.IndexOf([char]0) -ge 0 -or $Name -match '[\x00-\x1F]') { throw 'The classic DeployMaster installation folder name is invalid.' }
    $ChildDirectory = if ($ResolveRootVariable -or [string]::IsNullOrWhiteSpace($Directory)) { $Name } elseif ([string]::IsNullOrEmpty($Name)) { $Directory } else { "$Directory\$Name" }
    $Folders.Add([pscustomobject]@{
        ComponentIndex = $ComponentIndex
        Name           = $Name
        FullName       = $ChildDirectory
        Parent         = $Directory
        Depth          = $Depth
      })
    Read-DeployMasterClassicInstallTreeNodeList -Stream $Stream -Cursor $Cursor -EndOffset $EndOffset -RecordByOffset $RecordByOffset -FileEntries $FileEntries -ComponentIndex $ComponentIndex -Directory $ChildDirectory -GroupIndex $GroupIndex -Groups $Groups -Folders $Folders -InstalledFiles $InstalledFiles -Shortcuts $Shortcuts -UrlShortcuts $UrlShortcuts -ItemRecords $ItemRecords -Depth ($Depth + 1)
  }
  throw 'The classic DeployMaster installation tree is truncated.'
}

function Read-DeployMasterClassicInstallTree {
  <#
  .SYNOPSIS
    Decode the component-indexed folder forests and item streams in classic DeployMaster media.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its position.
  .PARAMETER StartOffset
    Absolute first folder opcode after the classic file-catalog columns.
  .PARAMETER EndOffset
    Exclusive boundary before the ordinary payload chain.
  .PARAMETER Record
    Validated zlib records that may be referenced by 0xFE item markers.
  .PARAMETER FileEntries
    Complete classic file-index namespace.
  .PARAMETER Components
    Ordered component catalog. The runtime serializes one root folder forest per component.
  .OUTPUTS
    Component-aware folders, item groups, installed files, shortcuts, consumed records, and the
    absolute first byte after the final component tree.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$StartOffset,
    [Parameter(Mandatory)][long]$EndOffset,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Components
  )

  if ($StartOffset -lt 0 -or $EndOffset -le $StartOffset -or $EndOffset -gt $Stream.Length) { throw 'The classic DeployMaster installation-tree range is invalid.' }
  $RecordByOffset = @{}
  foreach ($Candidate in $Record) {
    if ($Candidate.Offset -ge $StartOffset -and $Candidate.EndOffset -le $EndOffset) {
      $RecordByOffset[([long]$Candidate.Offset).ToString([Globalization.CultureInfo]::InvariantCulture)] = $Candidate
    }
  }
  $Groups = [Collections.Generic.List[object]]::new()
  $Folders = [Collections.Generic.List[object]]::new()
  $InstalledFiles = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $UrlShortcuts = [Collections.Generic.List[object]]::new()
  $ItemRecords = [Collections.Generic.List[object]]::new()
  $Cursor = [long]$StartOffset
  $GroupIndex = 0
  $TreeCount = [Math]::Max(1, $Components.Count)
  for ($ComponentIndex = 0; $ComponentIndex -lt $TreeCount; $ComponentIndex++) {
    $PreviousCursor = $Cursor
    $ResolvedComponentIndex = if ($Components.Count) { [Nullable[int]]$ComponentIndex } else { $null }
    Read-DeployMasterClassicInstallTreeNodeList -Stream $Stream -Cursor ([ref]$Cursor) -EndOffset $EndOffset -RecordByOffset $RecordByOffset -FileEntries $FileEntries -ComponentIndex $ResolvedComponentIndex -ResolveRootVariable -GroupIndex ([ref]$GroupIndex) -Groups $Groups -Folders $Folders -InstalledFiles $InstalledFiles -Shortcuts $Shortcuts -UrlShortcuts $UrlShortcuts -ItemRecords $ItemRecords
    if ($Cursor -le $PreviousCursor) { throw 'The classic DeployMaster installation tree did not advance.' }
  }
  return [pscustomobject]@{
    StartOffset    = $StartOffset
    EndOffset      = $Cursor
    Groups         = $Groups.ToArray()
    Folders        = $Folders.ToArray()
    InstalledFiles = $InstalledFiles.ToArray()
    Shortcuts      = $Shortcuts.ToArray()
    UrlShortcuts   = $UrlShortcuts.ToArray()
    ItemRecords    = $ItemRecords.ToArray()
    ComponentCount = $TreeCount
  }
}

function Read-DeployMasterClassicBehavior {
  <#
  .SYNOPSIS
    Decode structurally identifiable registry and file-association records from classic media.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its original position.
  .PARAMETER Record
    Validated classic zlib records indexed for the complete logical package.
  .PARAMETER Catalog
    Validated filename catalog and contiguous payload chain. Records between the filename catalog
    and first payload are the bounded classic behavior region.
  .PARAMETER FileEntries
    Complete classic file-index namespace used to validate installation-item references.
  .PARAMETER Components
    Ordered classic component catalog. Each component owns one serialized destination tree.
  .PARAMETER Route
    Catalog-selected classic registry and association grammars.
  .OUTPUTS
    Parsed registry writes, associations, their source records, and unclassified bounded records.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][psobject]$Catalog,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Components,
    [Parameter(Mandatory)][psobject]$Route
  )

  $PayloadStart = [long]$Catalog.Records[0].Offset
  $BehaviorRecords = @($Record | Where-Object {
      $_.Offset -ge $Catalog.FileNameRecord.EndOffset -and $_.EndOffset -le $PayloadStart
    } | Sort-Object Offset)
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $DeletedKeys = [Collections.Generic.List[object]]::new()
  $FileAssociations = [Collections.Generic.List[object]]::new()
  $RegistryRecords = [Collections.Generic.List[object]]::new()
  $AssociationRecords = [Collections.Generic.List[object]]::new()
  $ConsumedOffsets = [Collections.Generic.HashSet[long]]::new()

  # Raw folder opcodes and compressed item streams are interleaved. Decode the component-indexed
  # tree first, then classify only the standalone registry and association records that follow it.
  $InstallTree = Read-DeployMasterClassicInstallTree -Stream $Stream -StartOffset $Catalog.InstallTreeOffset -EndOffset $PayloadStart -Record $BehaviorRecords -FileEntries $FileEntries -Components $Components
  foreach ($ItemRecord in @($InstallTree.ItemRecords)) { $null = $ConsumedOffsets.Add([long]$ItemRecord.Offset) }

  foreach ($Candidate in $BehaviorRecords) {
    if ($ConsumedOffsets.Contains([long]$Candidate.Offset)) { continue }
    if ($Candidate.CompressedSize -gt 4194304) { continue }
    try { $Bytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $Candidate -MaximumBytes 4194304 }
    catch { continue }
    if ($Bytes.Length -eq 0) { continue }

    # Classic registry streams authenticate themselves with a root opcode followed by a literal
    # HKEY name. Exact stream consumption in the decoder prevents component or shortcut records
    # from being accepted merely because their first byte is also 0x01.
    if ($Bytes[0] -eq 1 -and $Bytes.Length -ge 7 -and [Text.Encoding]::ASCII.GetString($Bytes, 1, [Math]::Min(5, $Bytes.Length - 1)) -ceq 'HKEY_') {
      try {
        $Registry = ConvertFrom-DeployMasterRegistryBlock -Bytes $Bytes -ScopeValue 1 -Route $Route.RegistryRoute
        foreach ($Write in @($Registry.RegistryWrites)) { $RegistryWrites.Add($Write) }
        foreach ($DeletedKey in @($Registry.DeletedKeys)) { $DeletedKeys.Add($DeletedKey) }
        $RegistryRecords.Add($Candidate)
        $null = $ConsumedOffsets.Add([long]$Candidate.Offset)
        continue
      } catch { $Registry = $null }
    }

    # File-type records use their own form-feed string framing and one x86 executable index per
    # action. The extension grammar and exact end position reject unrelated legacy records.
    try {
      $Associations = @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $Bytes -Route $Route.AssociationRoute)
      if ($Associations.Count) {
        foreach ($Association in $Associations) { $FileAssociations.Add($Association) }
        $AssociationRecords.Add($Candidate)
        $null = $ConsumedOffsets.Add([long]$Candidate.Offset)
      }
    } catch { $Associations = @() }
  }

  return [pscustomobject][ordered]@{
    Registry              = [pscustomobject]@{ RegistryWrites = $RegistryWrites.ToArray(); DeletedKeys = $DeletedKeys.ToArray() }
    FileAssociations      = $FileAssociations.ToArray()
    RegistryRecords       = $RegistryRecords.ToArray()
    AssociationRecords    = $AssociationRecords.ToArray()
    InstallationFolders   = $InstallTree.Folders
    InstallItemGroups     = $InstallTree.Groups
    InstalledFiles        = $InstallTree.InstalledFiles
    Shortcuts             = $InstallTree.Shortcuts
    UrlShortcuts          = $InstallTree.UrlShortcuts
    InstallItemRecords    = $InstallTree.ItemRecords
    InstallTreeEndOffset  = $InstallTree.EndOffset
    UnclassifiedRecords   = @($BehaviorRecords | Where-Object { -not $ConsumedOffsets.Contains([long]$_.Offset) })
    BehaviorRecordCount   = $BehaviorRecords.Count
    RecognizedRecordCount = $ConsumedOffsets.Count
  }
}

function Read-DeployMasterClassicPackageData {
  <#
  .SYNOPSIS
    Parse the verified DeployMaster 2.x BZip2/zlib package route.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Route
    Catalog route selected from trusted PE identity and overlay magic.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Route
  )

  $PELayout = Get-PELayout -Stream $Stream
  $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
  $LogicalEndCandidates = Get-DeployMasterClassicLogicalEndCandidate -Stream $Stream -PELayout $PELayout
  $Runtime = Get-DeployMasterClassicRuntimeRecord -Stream $Stream -OverlayOffset $OverlayOffset -MaximumEndOffset (($LogicalEndCandidates | Measure-Object -Maximum).Maximum)
  $RecordStart = $Runtime.MarkerOffset + 4
  $Records = @(Get-DeployMasterClassicZlibRecord -Stream $Stream -StartOffset $RecordStart -EndOffset (($LogicalEndCandidates | Measure-Object -Maximum).Maximum))
  $ByOffset = @{}
  foreach ($Record in $Records) { $ByOffset[([long]$Record.Offset).ToString([Globalization.CultureInfo]::InvariantCulture)] = $Record }
  $LanguageRecord = $ByOffset[$RecordStart.ToString([Globalization.CultureInfo]::InvariantCulture)]
  if (-not $LanguageRecord) { throw 'The classic DeployMaster language record is missing.' }
  $IdentityRecord = $ByOffset[([long]$LanguageRecord.EndOffset).ToString([Globalization.CultureInfo]::InvariantCulture)]
  if (-not $IdentityRecord) { throw 'The classic DeployMaster identity record is missing.' }
  $LanguageBytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $LanguageRecord -MaximumBytes 4194304
  if ([Text.Encoding]::GetEncoding(1252).GetString($LanguageBytes) -notmatch '(?i)%s\s+Setup') { throw 'The classic DeployMaster language record is invalid.' }
  $IdentityBytes = Read-DeployMasterClassicZlibRecordData -Stream $Stream -Record $IdentityRecord -MaximumBytes 1048576
  $Identity = ConvertFrom-DeployMasterClassicIdentity -Bytes $IdentityBytes
  $Catalog = Find-DeployMasterClassicPayloadCatalog -Stream $Stream -Record $Records -LogicalEndCandidate $LogicalEndCandidates
  $Catalog = Complete-DeployMasterClassicFileCatalog -Stream $Stream -Record $Records -Catalog $Catalog -Identity $Identity -IdentityEnd $IdentityRecord.EndOffset
  $ComponentMetadata = Read-DeployMasterClassicComponentCatalog -Stream $Stream -Record $Records -Catalog $Catalog -IdentityEnd $IdentityRecord.EndOffset

  $FileEntries = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index -lt $Catalog.AllRecords.Count; $Index++) {
    $Record = $Catalog.AllRecords[$Index]
    $FileEntries.Add([pscustomobject]@{
        Index            = $Index
        Name             = [IO.Path]::GetFileName($Catalog.AllFileNames[$Index])
        FullName         = $Catalog.AllFileNames[$Index]
        Offset           = $Record.DataOffset
        RecordOffset     = $Record.Offset
        CompressedSize   = $Record.CompressedSize
        UncompressedSize = $Catalog.ExpandedSizes[$Index]
        EndOffset        = $Record.EndOffset
        Compression      = 'Zlib'
        Crc32            = $Catalog.Crc32Values[$Index]
        IsAuxiliary      = $Index -lt $Catalog.AuxiliaryCount
      })
  }
  $BehaviorMetadata = Read-DeployMasterClassicBehavior -Stream $Stream -Record $Records -Catalog $Catalog -FileEntries $FileEntries.ToArray() -Components $ComponentMetadata.Components -Route $Route
  return [pscustomobject]@{
    Route            = $Route
    PELayout         = $PELayout
    OverlayOffset    = $OverlayOffset
    LogicalEnd       = $Catalog.LogicalEnd
    Runtime          = $Runtime
    Header           = [pscustomobject]@{
      FormatProfile        = $Route.Id
      FormatVersion        = 2
      ObservedRuntimeRange = $Route.ObservedRuntimeRange
      ProfileEvidence      = $Route.Evidence
      LzmaProperties       = [byte[]]::new(0)
      CoreEntries          = @($Runtime)
    }
    LanguageBlock    = [pscustomobject]@{ Bytes = $LanguageBytes; Offset = $LanguageRecord.DataOffset; EndOffset = $LanguageRecord.EndOffset }
    IdentityBlock    = [pscustomobject]@{ Bytes = $IdentityBytes; Offset = $IdentityRecord.DataOffset; EndOffset = $IdentityRecord.EndOffset }
    FileNameBlock    = [pscustomobject]@{ Bytes = $Catalog.FileNameBytes; Offset = $Catalog.FileNameRecord.DataOffset; EndOffset = $Catalog.FileNameRecord.EndOffset }
    FileCatalog      = $Catalog
    Identity         = $Identity
    Components       = $ComponentMetadata.Components
    ComponentRecords = $ComponentMetadata.ComponentRecords
    BehaviorMetadata = $BehaviorMetadata
    FileEntries      = $FileEntries.ToArray()
  }
}

Export-ModuleMember -Function Test-DeployMasterClassicZlibHeader, Get-DeployMasterClassicLogicalEndCandidate, Get-DeployMasterClassicRuntimeRecord, Get-DeployMasterClassicZlibRecord, Read-DeployMasterClassicZlibRecordData, ConvertFrom-DeployMasterClassicFileNameBlock, Find-DeployMasterClassicPayloadCatalog, Complete-DeployMasterClassicFileCatalog, ConvertFrom-DeployMasterClassicDestinationTail, ConvertFrom-DeployMasterClassicComponentBlock, Read-DeployMasterClassicComponentCatalog, ConvertFrom-DeployMasterClassicIdentity, ConvertFrom-DeployMasterClassicInstallItemBlock, Read-DeployMasterClassicInstallTreeNodeList, Read-DeployMasterClassicInstallTree, Read-DeployMasterClassicBehavior, Read-DeployMasterClassicPackageData
