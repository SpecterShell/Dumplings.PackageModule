# SPDX-License-Identifier: MIT
# Static DeployMaster parser derived from controlled DeployMaster 7.7 builds,
# validated legacy packages, and the documented installer command-line behavior.
# Reference: https://www.deploymaster.com/manual.html

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-DeployMasterScopeInfo {
  <#
  .SYNOPSIS
    Convert the DeployMaster package scope byte to WinGet scope evidence
  .NOTES
    Controlled current-user, all-users, and dual-scope builds encode 0, 1,
    and 2 respectively at the normalized package-header scope offset.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][ValidateRange(0, 255)][int]$Value)

  switch ($Value) {
    0 { [pscustomobject]@{ Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false } }
    1 { [pscustomobject]@{ Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false } }
    2 { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true } }
    default { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @(); SupportsDualScope = $false } }
  }
}

function Get-DeployMasterPackageLocator {
  <#
  .SYNOPSIS
    Read and validate the fixed DeployMaster package locator at file offset 0x80
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [ValidateRange(74, [long]::MaxValue)][long]$MaximumIntegrityBytes = 1073741824
  )

  if (-not $Stream.CanSeek -or $Stream.Length -lt 0x98) { throw 'The file is too small for a DeployMaster package locator.' }
  $PackageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset 0x80 -Size 4)
  $IntegrityLength = [long](Read-BinaryInteger -Stream $Stream -Offset 0x84 -Size 4)
  $ExpectedCrc32 = [uint32](Read-BinaryInteger -Stream $Stream -Offset 0x88 -Size 4)
  $ExpectedFileSize = [uint64](Read-BinaryInteger -Stream $Stream -Offset 0x8C -Size 8)
  $Reserved = [uint32](Read-BinaryInteger -Stream $Stream -Offset 0x94 -Size 4)

  if ($PackageOffset -lt 512 -or $IntegrityLength -lt 70 -or $IntegrityLength -gt $MaximumIntegrityBytes) {
    throw 'The DeployMaster package locator contains invalid range values.'
  }
  if ($PackageOffset + $IntegrityLength -gt $Stream.Length) { throw 'The DeployMaster integrity region is truncated.' }
  if ($ExpectedFileSize -ne [uint64]$Stream.Length) { throw 'The DeployMaster package locator file-size check failed.' }

  $IntegrityStream = New-BoundedReadStream -Stream $Stream -Offset $PackageOffset -Length $IntegrityLength -LeaveOpen
  try { $ActualCrc32 = [uint32](Get-BinaryCrc32 -Stream $IntegrityStream -MaximumBytes $IntegrityLength) }
  finally { $IntegrityStream.Dispose() }
  if ($ActualCrc32 -ne $ExpectedCrc32) { throw 'The DeployMaster package integrity CRC32 check failed.' }

  [pscustomobject]@{
    LocatorOffset    = 0x80L
    PackageOffset    = $PackageOffset
    IntegrityLength  = $IntegrityLength
    PackageDataOffset = $PackageOffset + $IntegrityLength
    ExpectedCrc32    = $ExpectedCrc32
    ActualCrc32      = $ActualCrc32
    ExpectedFileSize = $ExpectedFileSize
    Reserved         = $Reserved
  }
}

function Get-DeployMasterPackageHeader {
  <#
  .SYNOPSIS
    Normalize legacy and current DeployMaster package-control layouts
  .DESCRIPTION
    Current packages have a 74-byte control header. Older packages omit one
    four-byte platform field and therefore use the same fields shifted by four
    bytes in a 70-byte header. Candidate core ranges select the valid layout.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Locator,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumCoreBytes = 1073741824
  )

  $Properties = Read-BinaryBytes -Stream $Stream -Offset $Locator.PackageOffset -Count 5
  $DictionarySize = [uint32][BitConverter]::ToUInt32($Properties, 1)
  if ($Properties[0] -gt 224 -or $DictionarySize -lt 65536 -or $DictionarySize -gt 1073741824) {
    throw 'The DeployMaster package has invalid LZMA properties.'
  }

  $Layouts = @(
    [pscustomobject]@{ Name = 'Current'; Shift = 0; HeaderSize = 74; Version = '7.7+' },
    [pscustomobject]@{ Name = 'Legacy'; Shift = -4; HeaderSize = 70; Version = 'Legacy' }
  )
  $Candidates = [Collections.Generic.List[object]]::new()
  foreach ($Layout in $Layouts) {
    $PrimaryOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x16 + $Layout.Shift) -Size 4)
    $PrimaryCompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x1A + $Layout.Shift) -Size 4)
    $PrimaryUncompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x1E + $Layout.Shift) -Size 4)
    $SecondaryOffsetValue = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x22 + $Layout.Shift) -Size 4)
    $SecondaryOffset = [long]$SecondaryOffsetValue
    $SecondaryCompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x26 + $Layout.Shift) -Size 4)
    $SecondaryUncompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x2A + $Layout.Shift) -Size 4)
    $LanguageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x2E + $Layout.Shift) -Size 4)
    $IntegrityEnd = $Locator.PackageOffset + $Locator.IntegrityLength
    $CoreEntries = [Collections.Generic.List[object]]::new()
    if ($PrimaryOffset -ne 0) {
      if ($PrimaryOffset -lt $Locator.PackageOffset + $Layout.HeaderSize -or $PrimaryCompressedSize -le 0 -or
          $PrimaryUncompressedSize -le 0 -or $PrimaryUncompressedSize -gt $MaximumCoreBytes -or
          $PrimaryOffset + $PrimaryCompressedSize -gt $IntegrityEnd) { continue }
      $CoreEntries.Add([pscustomobject]@{ Architecture = 'x86'; Offset = $PrimaryOffset; CompressedSize = $PrimaryCompressedSize; UncompressedSize = $PrimaryUncompressedSize })
    } elseif ($PrimaryCompressedSize -ne 0 -or $PrimaryUncompressedSize -ne 0) { continue }
    if ($SecondaryOffsetValue -notin 0, [uint32]::MaxValue) {
      if ($SecondaryOffset -lt $Locator.PackageOffset + $Layout.HeaderSize -or $SecondaryCompressedSize -le 0 -or
          $SecondaryUncompressedSize -le 0 -or $SecondaryUncompressedSize -gt $MaximumCoreBytes -or
          $SecondaryOffset + $SecondaryCompressedSize -gt $IntegrityEnd) { continue }
      $CoreEntries.Add([pscustomobject]@{ Architecture = 'x64'; Offset = $SecondaryOffset; CompressedSize = $SecondaryCompressedSize; UncompressedSize = $SecondaryUncompressedSize })
    } elseif ($SecondaryCompressedSize -ne 0 -or $SecondaryUncompressedSize -ne 0) { continue }
    if ($CoreEntries.Count -eq 0) { continue }
    $LastCoreEnd = ($CoreEntries | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum
    if ($LanguageOffset -lt $LastCoreEnd -or $LanguageOffset + 8 -gt $IntegrityEnd) { continue }

    $ScopeValue = [int](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x15 + $Layout.Shift) -Size 1)
    if ($ScopeValue -gt 2) { continue }
    $Candidates.Add([pscustomobject]@{
        Layout              = $Layout.Name
        FormatVersion       = $Layout.Version
        HeaderSize          = $Layout.HeaderSize
        ScopeValue          = $ScopeValue
        CoreEntries         = $CoreEntries.ToArray()
        SecondaryOffsetValue = $SecondaryOffsetValue
        LanguageBlockOffset = $LanguageOffset
      })
  }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster package-control layout could not be normalized unambiguously.' }

  $Candidate = $Candidates[0]
  $ScopeInfo = Get-DeployMasterScopeInfo -Value $Candidate.ScopeValue
  $PrimaryCore = @($Candidate.CoreEntries | Where-Object Architecture -eq 'x86' | Select-Object -First 1)
  $SecondaryCore = @($Candidate.CoreEntries | Where-Object Architecture -eq 'x64' | Select-Object -First 1)
  $ApplicationArchitectureMode = if ($PrimaryCore.Count -and $SecondaryCore.Count) {
    'x86AndX64Application'
  } elseif ($SecondaryCore.Count) {
    'x64Application'
  } elseif ($Candidate.SecondaryOffsetValue -eq [uint32]::MaxValue) {
    'x86ApplicationForX86WindowsOnly'
  } else {
    'x86ApplicationForX86AndX64Windows'
  }
  $OperatingSystemArchitectures = switch ($ApplicationArchitectureMode) {
    'x86ApplicationForX86WindowsOnly' { @('x86') }
    'x64Application' { @('x64') }
    default { @('x86', 'x64') }
  }
  $FirstCore = $Candidate.CoreEntries | Select-Object -First 1
  [pscustomobject]@{
    Layout                  = $Candidate.Layout
    FormatVersion           = $Candidate.FormatVersion
    HeaderSize              = $Candidate.HeaderSize
    LzmaProperties          = $Properties
    LzmaPropertyByte        = [byte]$Properties[0]
    DictionarySize          = $DictionarySize
    ScopeValue              = $Candidate.ScopeValue
    Scope                   = $ScopeInfo.Scope
    DefaultScope            = $ScopeInfo.DefaultScope
    SupportedScopes         = $ScopeInfo.SupportedScopes
    SupportsDualScope       = $ScopeInfo.SupportsDualScope
    CoreOffset              = $FirstCore.Offset
    CoreCompressedSize      = $FirstCore.CompressedSize
    CoreUncompressedSize    = $FirstCore.UncompressedSize
    CoreEntries             = $Candidate.CoreEntries
    ApplicationArchitectureMode = $ApplicationArchitectureMode
    ApplicationArchitectures = @($Candidate.CoreEntries | Select-Object -ExpandProperty Architecture)
    SupportedOperatingSystemArchitectures = $OperatingSystemArchitectures
    LanguageBlockOffset     = $Candidate.LanguageBlockOffset
  }
}

function Read-DeployMasterCompressedBlock {
  <#
  .SYNOPSIS
    Decode one size-prefixed raw LZMA block within the integrity region
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][long]$Limit,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 16777216
  )

  if ($Offset -lt 0 -or $Offset + 8 -gt $Limit) { throw 'The DeployMaster compressed-block header is outside the package bounds.' }
  $UncompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
  $CompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4)
  if ($UncompressedSize -le 0 -or $UncompressedSize -gt $MaximumBytes -or $CompressedSize -le 0 -or $Offset + 8 + $CompressedSize -gt $Limit) {
    throw 'The DeployMaster compressed block contains invalid size values.'
  }

  $InputStream = New-BoundedReadStream -Stream $Stream -Offset ($Offset + 8) -Length $CompressedSize -LeaveOpen
  $OutputStream = [IO.MemoryStream]::new()
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes $MaximumBytes -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize
    $Bytes = $OutputStream.ToArray()
  } finally {
    $InputStream.Dispose()
    $OutputStream.Dispose()
  }

  [pscustomobject]@{
    Offset           = $Offset
    DataOffset       = $Offset + 8
    CompressedSize   = $CompressedSize
    UncompressedSize = $UncompressedSize
    EndOffset        = $Offset + 8 + $CompressedSize
    Bytes            = $Bytes
  }
}

function ConvertFrom-DeployMasterIdentity {
  <#
  .SYNOPSIS
    Convert the structured DeployMaster identity block to package metadata
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$ScopeValue
  )

  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  try { $Fields = $Utf8.GetString($Bytes).Split([char]12) }
  catch { throw 'The DeployMaster identity block is not valid UTF-8.' }
  if ($Fields.Count -lt 19) { throw 'The DeployMaster identity block is incomplete.' }

  $MachineLocationField = [string]$Fields[11]
  $LocationMarker = if ($MachineLocationField.Length) { [int][char]$MachineLocationField[0] } else { 0 }
  $MachineInstallLocation = $MachineLocationField.TrimStart([char[]](0, 1, 2, 3))
  $UserInstallLocation = [string]$Fields[12]
  $LicenseFileName = ([string]$Fields[8]).TrimStart('*')
  $ReleaseDate = $null
  $ReleaseDateValue = 0.0
  if ([double]::TryParse([string]$Fields[5], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ReleaseDateValue)) {
    try { $ReleaseDate = [datetime]::FromOADate($ReleaseDateValue).Date } catch {}
  }

  [pscustomobject]@{
    Publisher               = [string]$Fields[0]
    PublisherUrl            = [string]$Fields[1]
    DisplayName             = [string]$Fields[2]
    PackageUrl              = [string]$Fields[3]
    DisplayVersion          = [string]$Fields[4]
    ReleaseDateValue        = [string]$Fields[5]
    ReleaseDate             = $ReleaseDate
    Copyright               = [string]$Fields[6]
    LicenseUrl              = [string]$Fields[7]
    LicenseFileName         = $LicenseFileName
    MachineInstallLocation  = $MachineInstallLocation
    UserInstallLocation     = $UserInstallLocation
    CommonFilesLocation     = [string]$Fields[13]
    CommonPublisherLocation = [string]$Fields[14]
    MachineMenuLocation     = [string]$Fields[15]
    UserMenuLocation        = [string]$Fields[16]
    CommonDataLocation      = [string]$Fields[17]
    UserDataLocation        = [string]$Fields[18]
    LocationMarker          = $LocationMarker
    LocationMarkerMatchesScope = $LocationMarker -eq @{
      0 = 2
      1 = 1
      2 = 3
    }[$ScopeValue]
    Fields                  = $Fields
  }
}

function Get-DeployMasterFileEntry {
  <#
  .SYNOPSIS
    Read the bounded DeployMaster file-offset and size tables
  .DESCRIPTION
    The file table stores a run of absolute offsets followed by parallel raw
    and stored-size arrays. File names immediately precede the arrays; the
    mandatory license file name is carried by the identity block.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Identity,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][long]$PackageDataOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][ValidateSet('Current', 'Legacy')][string]$TableKind,
    [ValidateRange(2, 4096)][int]$MaximumEntries = 4096,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumMetadataBytes = 33554432
  )

  $MetadataLength = $PackageDataOffset - $IdentityEnd
  if ($MetadataLength -le 0 -or $MetadataLength -gt $MaximumMetadataBytes -or $MetadataLength -gt [int]::MaxValue) {
    throw 'The DeployMaster file-table region is outside the configured bounds.'
  }
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $IdentityEnd -Count ([int]$MetadataLength)
  $Candidates = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index + 48 -le $Metadata.Length; $Index++) {
    $FirstOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index)
    $SecondOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index + 8)
    if ($FirstOffset -lt [uint64]$IdentityEnd -or $SecondOffset -le $FirstOffset -or $SecondOffset -ge [uint64]$Stream.Length) { continue }

    $Boundaries = [Collections.Generic.List[long]]::new()
    $Cursor = $Index
    while ($Boundaries.Count -lt $MaximumEntries -and $Cursor + 8 -le $Metadata.Length) {
      $Value = [uint64][BitConverter]::ToUInt64($Metadata, $Cursor)
      if ($Value -lt [uint64]$IdentityEnd -or $Value -ge [uint64]$Stream.Length -or ($Boundaries.Count -and $Value -le [uint64]$Boundaries[$Boundaries.Count - 1])) { break }
      $Boundaries.Add([long]$Value)
      $Cursor += 8
    }
    if ($Boundaries.Count -lt 2 -or $Boundaries -notcontains $PackageDataOffset) { continue }

    foreach ($CandidateTableKind in $TableKind) {
      $EntryCount = if ($CandidateTableKind -eq 'Current') { $Boundaries.Count } else { $Boundaries.Count + 1 }
      if ($EntryCount -gt $MaximumEntries -or $Cursor + (16 * $EntryCount) -gt $Metadata.Length) { continue }
      $RawSizes = [Collections.Generic.List[long]]::new()
      $StoredSizes = [Collections.Generic.List[long]]::new()
      $Valid = $true
      for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
        $Value = [uint64][BitConverter]::ToUInt64($Metadata, $Cursor + (8 * $EntryIndex))
        if ($Value -eq 0 -or $Value -gt [uint64][long]::MaxValue) { $Valid = $false; break }
        $RawSizes.Add([long]$Value)
      }
      if (-not $Valid) { continue }
      $StoredSizeOffset = $Cursor + (8 * $EntryCount)
      for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
        $Value = [uint64][BitConverter]::ToUInt64($Metadata, $StoredSizeOffset + (8 * $EntryIndex))
        if ($Value -eq 0 -or $Value -gt [uint64]$RawSizes[$EntryIndex]) { $Valid = $false; break }
        $StoredSizes.Add([long]$Value)
      }
      if (-not $Valid) { continue }

      $Offsets = [Collections.Generic.List[long]]::new()
      if ($CandidateTableKind -eq 'Current') {
        foreach ($Boundary in $Boundaries) { $Offsets.Add($Boundary) }
      } else {
        # Legacy packages keep the mandatory license block before the file
        # boundary table as [stored-size][raw-size][raw LZMA bytes].
        $LicenseOffsets = [Collections.Generic.List[long]]::new()
        for ($LicenseHeader = 0; $LicenseHeader + 8 + $StoredSizes[0] -le $Index; $LicenseHeader++) {
          if ([BitConverter]::ToUInt32($Metadata, $LicenseHeader) -eq $StoredSizes[0] -and
              [BitConverter]::ToUInt32($Metadata, $LicenseHeader + 4) -eq $RawSizes[0]) {
            $LicenseOffsets.Add($IdentityEnd + $LicenseHeader + 8)
          }
        }
        if ($LicenseOffsets.Count -ne 1) { continue }
        $Offsets.Add($LicenseOffsets[0])
        foreach ($Boundary in $Boundaries) { $Offsets.Add($Boundary) }
      }
      for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
        if ($Offsets[$EntryIndex] + $StoredSizes[$EntryIndex] -gt $Stream.Length) { $Valid = $false; break }
      }
      if ($Valid) {
        $Candidates.Add([pscustomobject]@{
            TableKind = $CandidateTableKind
            TableOffset = $Index
            Offsets = $Offsets.ToArray()
            RawSizes = $RawSizes.ToArray()
            StoredSizes = $StoredSizes.ToArray()
          })
      }
    }
  }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster file table could not be located unambiguously.' }

  $Candidate = $Candidates[0]
  $Names = [Collections.Generic.List[string]]::new()
  if (-not [string]::IsNullOrWhiteSpace($Identity.LicenseFileName)) { $Names.Add($Identity.LicenseFileName) }
  $RemainingNameCount = $Candidate.Offsets.Count - $Names.Count
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  $PayloadNames = @()

  # Smaller current packages keep the CRLF-delimited payload names directly
  # before the arrays. Multi-architecture and legacy packages compress them.
  try {
    $NameCursor = $Candidate.TableOffset
    $ReverseNames = [Collections.Generic.List[string]]::new()
    for ($NameIndex = 0; $NameIndex -lt $RemainingNameCount; $NameIndex++) {
      if ($NameCursor -lt 2 -or $Metadata[$NameCursor - 2] -ne 13 -or $Metadata[$NameCursor - 1] -ne 10) { throw 'The plain file-name table is absent.' }
      $LineEnd = $NameCursor - 2
      $LineStart = $LineEnd
      while ($LineStart -gt 0) {
        $Byte = $Metadata[$LineStart - 1]
        if ($Byte -lt 32 -or $Byte -eq 127 -or $Byte -eq 255) { break }
        $LineStart--
      }
      if ($LineStart -eq $LineEnd) { throw 'The plain file-name table contains an empty entry.' }
      $ReverseNames.Add($Utf8.GetString($Metadata, $LineStart, $LineEnd - $LineStart))
      $NameCursor = $LineStart
    }
    $PayloadNames = @($ReverseNames.ToArray())
    [array]::Reverse($PayloadNames)
  } catch { $PayloadNames = @() }

  if ($PayloadNames.Count -ne $RemainingNameCount) {
    $DecodedNameLists = [Collections.Generic.List[object]]::new()
    $MinimumHeaderOffset = [Math]::Max(0, $Candidate.TableOffset - 1048576)
    for ($BlockOffset = $MinimumHeaderOffset; $BlockOffset + 8 -le $Candidate.TableOffset; $BlockOffset++) {
      $RawSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset)
      $StoredSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset + 4)
      $BlockEnd = $BlockOffset + 8 + $StoredSize
      if ($RawSize -eq 0 -or $RawSize -gt 1048576 -or $StoredSize -eq 0 -or $StoredSize -gt $RawSize -or $BlockEnd -gt $Candidate.TableOffset -or $Candidate.TableOffset - $BlockEnd -gt 16) { continue }
      $InputStream = [IO.MemoryStream]::new($Metadata, $BlockOffset + 8, [int]$StoredSize, $false, $true)
      $OutputStream = [IO.MemoryStream]::new()
      try {
        $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes 1048576 -Properties $Properties -CompressedSize $StoredSize -UncompressedSize $RawSize
        $Text = $Utf8.GetString($OutputStream.ToArray())
        $DecodedNames = @($Text -split "`r`n" | Where-Object { -not [string]::IsNullOrEmpty($_) })
        if ($DecodedNames.Count -eq $RemainingNameCount) { $DecodedNameLists.Add($DecodedNames) }
      } catch {
      } finally {
        $InputStream.Dispose()
        $OutputStream.Dispose()
      }
    }
    if ($DecodedNameLists.Count -ne 1) { throw 'The DeployMaster file-name table could not be decoded unambiguously.' }
    $PayloadNames = @($DecodedNameLists[0])
  }
  foreach ($PayloadName in $PayloadNames) { $Names.Add($PayloadName) }
  if ($Names.Count -ne $Candidate.Offsets.Count) { throw 'The DeployMaster file-name and offset table counts differ.' }

  for ($EntryIndex = 0; $EntryIndex -lt $Names.Count; $EntryIndex++) {
    [pscustomobject]@{
      Index            = $EntryIndex
      Name             = $Names[$EntryIndex]
      FullName         = $Names[$EntryIndex]
      Offset           = $Candidate.Offsets[$EntryIndex]
      CompressedSize   = $Candidate.StoredSizes[$EntryIndex]
      UncompressedSize = $Candidate.RawSizes[$EntryIndex]
      Compression      = if ($Candidate.StoredSizes[$EntryIndex] -eq $Candidate.RawSizes[$EntryIndex]) { 'Store' } else { 'Lzma' }
    }
  }
}

function ConvertFrom-DeployMasterFileAssociationBlock {
  <#
  .SYNOPSIS
    Parse a structured DeployMaster file-type metadata record
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -lt 2) { throw 'The DeployMaster file-type record is too small.' }
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  $Cursor = 0
  $Count = [int]$Bytes[$Cursor++]
  if ($Count -lt 1 -or $Count -gt 64) { throw 'The DeployMaster file-type count is invalid.' }

  function ReadAssociationUInt16([ref]$Position) {
    if ($Position.Value + 2 -gt $Bytes.Length) { throw 'The DeployMaster file-type record is truncated.' }
    $Value = [uint16][BitConverter]::ToUInt16($Bytes, $Position.Value)
    $Position.Value += 2
    return $Value
  }
  function ReadAssociationInt16([ref]$Position) {
    if ($Position.Value + 2 -gt $Bytes.Length) { throw 'The DeployMaster file-type record is truncated.' }
    $Value = [int16][BitConverter]::ToInt16($Bytes, $Position.Value)
    $Position.Value += 2
    return $Value
  }
  function ReadAssociationString([ref]$Position) {
    $Length = [int](ReadAssociationUInt16 -Position $Position)
    if ($Position.Value + $Length -gt $Bytes.Length) { throw 'The DeployMaster file-type string is truncated.' }
    $Value = $Utf8.GetString($Bytes, $Position.Value, $Length)
    $Position.Value += $Length
    return $Value
  }

  $Associations = [Collections.Generic.List[object]]::new()
  for ($AssociationIndex = 0; $AssociationIndex -lt $Count; $AssociationIndex++) {
    if ($Cursor -ge $Bytes.Length -or $Bytes[$Cursor] -notin 0, 1) { throw 'The DeployMaster file-type default flag is invalid.' }
    $CreateByDefault = [bool]$Bytes[$Cursor++]
    $Description = ReadAssociationString -Position ([ref]$Cursor)
    $Extension = ReadAssociationString -Position ([ref]$Cursor)
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') { throw 'The DeployMaster file-type extension is invalid.' }
    $Icon32FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 32-bit icon record is truncated.' }
    $Icon32ResourceIndex = [int]$Bytes[$Cursor++]
    $Icon64FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 64-bit icon record is truncated.' }
    $Icon64ResourceIndex = [int]$Bytes[$Cursor++]
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster file-type action count is missing.' }
    $ActionCount = [int]$Bytes[$Cursor++]
    if ($ActionCount -gt 64) { throw 'The DeployMaster file-type action count is invalid.' }
    $Actions = [Collections.Generic.List[object]]::new()
    for ($ActionIndex = 0; $ActionIndex -lt $ActionCount; $ActionIndex++) {
      $Actions.Add([pscustomobject]@{
          Name                  = ReadAssociationString -Position ([ref]$Cursor)
          Executable32FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
          Executable64FileIndex = ReadAssociationInt16 -Position ([ref]$Cursor)
          Parameters            = ReadAssociationString -Position ([ref]$Cursor)
        })
    }
    $Associations.Add([pscustomobject]@{
        Extension           = $Extension.ToLowerInvariant()
        FileExtension       = $Extension.TrimStart('.').ToLowerInvariant()
        Description         = $Description
        CreateByDefault     = $CreateByDefault
        Icon32FileIndex     = $Icon32FileIndex
        Icon32ResourceIndex = $Icon32ResourceIndex
        Icon64FileIndex     = $Icon64FileIndex
        Icon64ResourceIndex = $Icon64ResourceIndex
        Actions             = $Actions.ToArray()
      })
  }
  if ($Cursor -ne $Bytes.Length) { throw 'The DeployMaster file-type record has trailing data.' }
  $Associations.ToArray()
}

function Get-DeployMasterFileAssociation {
  <#
  .SYNOPSIS
    Locate and decode structured file-type records in package metadata
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][long]$PackageDataOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [ValidateRange(1, 128)][int]$MaximumBlocks = 128
  )

  $MetadataLength = $PackageDataOffset - $IdentityEnd
  if ($MetadataLength -le 0 -or $MetadataLength -gt 33554432 -or $MetadataLength -gt [int]::MaxValue) { return }
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $IdentityEnd -Count ([int]$MetadataLength)
  $Associations = [Collections.Generic.List[object]]::new()
  $DecodedBlockCount = 0
  for ($BlockOffset = 0; $BlockOffset + 9 -le $Metadata.Length -and $DecodedBlockCount -lt $MaximumBlocks; $BlockOffset++) {
    $RawSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset)
    $StoredSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset + 4)
    if ($RawSize -eq 0 -or $RawSize -gt 1048576 -or $StoredSize -eq 0 -or $StoredSize -gt $RawSize -or $BlockOffset + 8 + $StoredSize -gt $Metadata.Length) { continue }
    $InputStream = [IO.MemoryStream]::new($Metadata, $BlockOffset + 8, [int]$StoredSize, $false, $true)
    $OutputStream = [IO.MemoryStream]::new()
    try {
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes 1048576 -Properties $Properties -CompressedSize $StoredSize -UncompressedSize $RawSize
      $DecodedBlockCount++
      $Parsed = @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $OutputStream.ToArray())
      foreach ($Association in $Parsed) { $Associations.Add($Association) }
      $BlockOffset += 7 + $StoredSize
    } catch {
    } finally {
      $InputStream.Dispose()
      $OutputStream.Dispose()
    }
  }
  $Associations.ToArray()
}

function Read-DeployMasterPackageData {
  <#
  .SYNOPSIS
    Parse one DeployMaster package from an already-open installer stream
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  $Locator = Get-DeployMasterPackageLocator -Stream $Stream
  $Header = Get-DeployMasterPackageHeader -Stream $Stream -Locator $Locator
  $IntegrityEnd = $Locator.PackageOffset + $Locator.IntegrityLength
  $LanguageBlock = Read-DeployMasterCompressedBlock -Stream $Stream -Offset $Header.LanguageBlockOffset -Properties $Header.LzmaProperties -Limit $IntegrityEnd
  $IdentityBlock = Read-DeployMasterCompressedBlock -Stream $Stream -Offset $LanguageBlock.EndOffset -Properties $Header.LzmaProperties -Limit $IntegrityEnd
  $Identity = ConvertFrom-DeployMasterIdentity -Bytes $IdentityBlock.Bytes -ScopeValue $Header.ScopeValue
  $Warnings = [Collections.Generic.List[string]]::new()
  if (-not $Identity.LocationMarkerMatchesScope) { $Warnings.Add('The DeployMaster identity scope marker does not match the package-control scope byte.') }
  try { $FileEntries = @(Get-DeployMasterFileEntry -Stream $Stream -Identity $Identity -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties -TableKind $Header.Layout) }
  catch {
    $FileEntries = @()
    $Warnings.Add("The DeployMaster payload file table was not decoded: $($_.Exception.Message)")
  }
  try { $FileAssociations = @(Get-DeployMasterFileAssociation -Stream $Stream -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties) }
  catch {
    $FileAssociations = @()
    $Warnings.Add("The DeployMaster file-type table was not decoded: $($_.Exception.Message)")
  }

  [pscustomobject]@{
    Locator       = $Locator
    Header        = $Header
    LanguageBlock = $LanguageBlock
    IdentityBlock = $IdentityBlock
    Identity      = $Identity
    FileEntries   = $FileEntries
    FileAssociations = $FileAssociations
    Warnings      = @($Warnings)
  }
}

function ConvertTo-DeployMasterRegistryWrite {
  <#
  .SYNOPSIS
    Build the explicit built-in DeployMaster uninstall-entry evidence
  #>
  param (
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][string]$Name,
    [AllowNull()][object]$Value
  )

  $Root = switch ($PackageData.Header.ScopeValue) { 0 { 'HKCU' } 1 { 'HKLM' } default { 'SHCTX' } }
  [pscustomobject]@{
    Root     = $Root
    Key      = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($PackageData.Identity.DisplayName)"
    Name     = $Name
    Value    = $Value
    Type     = 'REG_SZ'
    Evidence = 'DeployMaster structured identity and built-in uninstaller configuration'
  }
}

function Get-DeployMasterInfo {
  <#
  .SYNOPSIS
    Read structured DeployMaster identity, scope, ARP, and payload evidence
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $PackageData = Read-DeployMasterPackageData -Stream $Stream
      $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
      $PELayout = Get-PELayout -Stream $Stream
    } finally { $Stream.Dispose() }

    if ($OverlayOffset -ne $PackageData.Locator.PackageOffset) { throw 'The DeployMaster package locator does not point to the PE overlay.' }
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $VersionStrings = Get-PEVersionStringTable -Path $File.FullName
    $RuntimeProductName = ([string]$VersionInfo.ProductName).Trim()
    $RuntimeComments = ([string]$VersionStrings.Comments).Trim()
    if ($RuntimeProductName -notmatch '(?i)DeployMaster' -and $RuntimeComments -notmatch '(?i)DeployMaster') { throw 'The validated package overlay is not paired with a DeployMaster runtime identity.' }

    $Identity = $PackageData.Identity
    $InstallLocation = switch ($PackageData.Header.ScopeValue) {
      0 { $Identity.UserInstallLocation }
      1 { $Identity.MachineInstallLocation }
      default { $null }
    }
    $RegistryWrites = @(
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name DisplayName -Value $Identity.DisplayName
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name DisplayVersion -Value $Identity.DisplayVersion
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name Publisher -Value $Identity.Publisher
      ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Name InstallLocation -Value $InstallLocation
    )
    $FileExtensions = @($PackageData.FileAssociations | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    $RegistryAssociationInfo = [pscustomobject]@{
      Protocols                 = @()
      FileExtensions            = $FileExtensions
      ProtocolAssociations      = @()
      FileExtensionAssociations = $PackageData.FileAssociations
      RegistryWrites            = @()
      Warnings                  = @()
    }
    $Warnings = [Collections.Generic.List[string]]::new()
    foreach ($Warning in $PackageData.Warnings) { $Warnings.Add($Warning) }
    if ($PackageData.Header.SupportsDualScope) { $Warnings.Add('This DeployMaster package supports both user and machine scope; validate the default scope and any elevation-sensitive behavior in a VM.') }
    $Warnings.Add('DeployMaster custom registry action tables are not decoded; validate package-specific ARP overrides and first-run associations in a VM.')
    if ($PackageData.FileAssociations.Actions | Where-Object { $_.Executable32FileIndex -lt 0 -and $_.Executable64FileIndex -lt 0 }) {
      $Warnings.Add('One or more DeployMaster file-type actions do not resolve to packaged executable indexes and will not create an open command.')
    }
    $InstallerArchitecture = switch ($PELayout.MachineName) { 'I386' { 'x86' } 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { $null } }
    $ApplicationArchitectureMode = if ($PackageData.Header.ApplicationArchitectureMode -eq 'x64Application') {
      if ($InstallerArchitecture -eq 'x86') { 'x64ApplicationWithX86InstallerStub' } else { 'x64ApplicationWithX64Installer' }
    } else { $PackageData.Header.ApplicationArchitectureMode }

    [pscustomobject]@{
      InstallerType              = 'DeployMaster'
      ProductCode                = $Identity.DisplayName
      ProductCodeEvidence        = 'DeployMaster structured identity and built-in uninstall-key convention'
      PackageName                = $Identity.DisplayName
      DisplayName                = $Identity.DisplayName
      ProductName                = $Identity.DisplayName
      DisplayVersion             = $Identity.DisplayVersion
      Publisher                  = $Identity.Publisher
      PublisherUrl               = $Identity.PublisherUrl
      PackageUrl                 = $Identity.PackageUrl
      Copyright                  = $Identity.Copyright
      ReleaseDate                = $Identity.ReleaseDate
      InstallLocation            = $InstallLocation
      MachineInstallLocation     = $Identity.MachineInstallLocation
      UserInstallLocation        = $Identity.UserInstallLocation
      RuntimeProductName         = $RuntimeProductName
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = $PackageData.Header.Scope
      DefaultScope               = $PackageData.Header.DefaultScope
      SupportedScopes            = $PackageData.Header.SupportedScopes
      SupportsDualScope          = $PackageData.Header.SupportsDualScope
      InstallerArchitecture      = $InstallerArchitecture
      ApplicationArchitectureMode = $ApplicationArchitectureMode
      ApplicationArchitectures   = $PackageData.Header.ApplicationArchitectures
      SupportedArchitectures     = $PackageData.Header.ApplicationArchitectures
      SupportedOperatingSystemArchitectures = $PackageData.Header.SupportedOperatingSystemArchitectures
      RequestedExecutionLevel    = Get-PERequestedExecutionLevel -Path $File.FullName
      RegistryWrites             = $RegistryWrites
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      FileAssociations           = $PackageData.FileAssociations
      WritesAppsAndFeaturesEntry = $true
      FileEntries                = $PackageData.FileEntries
      ExtractedFiles             = @($PackageData.FileEntries | Select-Object -ExpandProperty FullName)
      OverlayInfo                = [pscustomobject]@{
        OverlayOffset     = $PackageData.Locator.PackageOffset
        OverlayLength     = $File.Length - $PackageData.Locator.PackageOffset
        IntegrityLength   = $PackageData.Locator.IntegrityLength
        ExpectedCrc32     = $PackageData.Locator.ExpectedCrc32
        ActualCrc32       = $PackageData.Locator.ActualCrc32
        DictionarySize    = $PackageData.Header.DictionarySize
        FormatVersion     = $PackageData.Header.FormatVersion
        PackageDataOffset = $PackageData.Locator.PackageDataOffset
      }
      CanExpand                  = $true
      Warnings                   = @($Warnings | Select-Object -Unique)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.DeployMaster'; ParserMajor = 2; Sources = @('DeployMaster 0x80 package locator', 'CRC32-protected package-control header', 'bounded LZMA identity and file-type blocks', 'controlled scope and architecture builder outputs') }
    }
  }
}

function Export-DeployMasterRange {
  <#
  .SYNOPSIS
    Export one stored or raw-LZMA DeployMaster range
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Entry,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][long]$MaximumBytes
  )

  $Output = [IO.File]::Open($DestinationPath, 'CreateNew', 'Write', 'None')
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Entry.Offset -Length $Entry.CompressedSize -LeaveOpen
  try {
    if ($Entry.Compression -eq 'Store') {
      $null = Copy-BoundedStream -Source $InputStream -Destination $Output -MaximumBytes $MaximumBytes -ExpectedBytes $Entry.UncompressedSize
    } else {
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $Output -MaximumBytes $MaximumBytes -Properties $Properties -CompressedSize $Entry.CompressedSize -UncompressedSize $Entry.UncompressedSize
    }
  } finally {
    $InputStream.Dispose()
    $Output.Dispose()
  }
  Get-Item -LiteralPath $DestinationPath -Force
}

function Expand-DeployMasterInstaller {
  <#
  .SYNOPSIS
    Expand validated DeployMaster runtime, metadata, and payload files
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-DeployMaster-$([guid]::NewGuid().ToString('N'))") }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Results = [Collections.Generic.List[object]]::new()
    $ExpandedBytes = 0L
    try {
      $PackageData = Read-DeployMasterPackageData -Stream $Stream
      $Items = [Collections.Generic.List[object]]::new()
      foreach ($Core in $PackageData.Header.CoreEntries) {
        $Items.Add([pscustomobject]@{ FullName = "Runtime/DeployMasterCore-$($Core.Architecture).exe"; Kind = 'Compressed'; Offset = $Core.Offset; CompressedSize = $Core.CompressedSize; UncompressedSize = $Core.UncompressedSize; Compression = 'Lzma' })
      }
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Language.txt'; Kind = 'Bytes'; Bytes = $PackageData.LanguageBlock.Bytes; UncompressedSize = $PackageData.LanguageBlock.Bytes.Length })
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Identity.txt'; Kind = 'Bytes'; Bytes = $PackageData.IdentityBlock.Bytes; UncompressedSize = $PackageData.IdentityBlock.Bytes.Length })
      foreach ($Entry in $PackageData.FileEntries) {
        $Items.Add([pscustomobject]@{ FullName = "Payload/$($Entry.FullName)"; Kind = 'Compressed'; Offset = $Entry.Offset; CompressedSize = $Entry.CompressedSize; UncompressedSize = $Entry.UncompressedSize; Compression = $Entry.Compression })
      }

      foreach ($Item in $Items) {
        if (-not (Test-ExtractionPattern -Path $Item.FullName -Pattern $Name)) { continue }
        if ($ExpandedBytes + $Item.UncompressedSize -gt $MaximumExpandedBytes) { throw "The DeployMaster expansion exceeds the $MaximumExpandedBytes-byte output limit." }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Item.FullName
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        if (Test-Path -LiteralPath $OutputPath) { throw "The DeployMaster payload contains a duplicate output path: $($Item.FullName)" }
        if ($Item.Kind -eq 'Bytes') {
          [IO.File]::WriteAllBytes($OutputPath, $Item.Bytes)
          $Result = Get-Item -LiteralPath $OutputPath -Force
        } else {
          $Result = Export-DeployMasterRange -Stream $Stream -Entry $Item -Properties $PackageData.Header.LzmaProperties -DestinationPath $OutputPath -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes)
        }
        $ExpandedBytes += $Item.UncompressedSize
        $Results.Add($Result)
      }
    } finally { $Stream.Dispose() }
    $Results.ToArray()
  }
}

function Test-DeployMaster {
  <#
  .SYNOPSIS
    Test whether a file contains a validated DeployMaster package
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-DeployMasterInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal URL protocol names from DeployMaster registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal file extensions from DeployMaster registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster product version
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster package display name
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayName }
}

function Read-PublisherFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster publisher
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromDeployMaster {
  <#
  .SYNOPSIS
    Read the built-in DeployMaster uninstall-key identity
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).ProductCode }
}

function Read-ScopeFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster installation scope
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-DeployMasterInfo, Expand-DeployMasterInstaller, Test-DeployMaster, Read-ProtocolsFromDeployMaster, Read-FileExtensionsFromDeployMaster, Read-ProductVersionFromDeployMaster, Read-ProductNameFromDeployMaster, Read-PublisherFromDeployMaster, Read-ProductCodeFromDeployMaster, Read-ScopeFromDeployMaster
