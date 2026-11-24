# SPDX-License-Identifier: Apache-2.0
#
# InstallForge parser, independently implemented from compiled media and the
# public InstallForge documentation:
# - https://github.com/soner-boztas/installforge/releases
# - https://installforge.net/docs/
# - https://installforge.net/docs/release-notes/
# - https://installforge.net/docs/using-installforge/command-line-interface/
# - https://installforge.net/docs/getting-started/predefined-constants/
#
# Binary structures consumed by this module:
#
#   InstallForge 1.2.x-1.3.x
#   PE image
#   `-- overlay
#       +-- optional runtime prefix
#       +-- Microsoft Cabinet (MSCF)
#       |   `-- SC.dat and operation tables
#       +-- optional separator
#       `-- ZIP payload
#
#   InstallForge 1.4.x
#   PE image
#   +-- .rsrc/RCDATA/SETUPCONFIGURATION
#   |   `-- 7z configuration archive
#   |       `-- SC.dat and operation tables
#   `-- overlay
#       +-- 13-byte JGTFUVQ`TUBSU marker + 8 observed bytes
#       `-- GZip stream -> TAR payload
#
#   InstallForge 1.5+
#   PE image
#   +-- .rsrc/RCDATA/SETUPCONFIGURATION -> 7z configuration archive
#   `-- overlay
#       +-- 13-byte JGTFUVQ`TUBSU marker + 8 observed bytes
#       `-- 7z payload
#
# CAB size fields, ZIP central-directory coordinates, 7z next-header ranges,
# and PE resources are validated before their contents are opened. Modern path
# segments are Base64-encoded UTF-16LE. Registry.dat consists of four CRLF text
# fields followed immediately by one UInt32 LE removal flag. No setup, payload,
# command, or uninstaller is loaded or executed.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallForgeMaximumConfigurationBytes = 16MB
$Script:InstallForgeMaximumArchiveBytes = 4GB
$Script:InstallForgeMaximumEntryBytes = 256MB
$Script:InstallForgeMaximumEntries = 65536
$Script:InstallForgeMaximumExpandedBytes = 16GB
$Script:InstallForgeMaximumAnalysisBytes = 512MB
$Script:InstallForgeMaximumAnalysisFiles = 32
$Script:InstallForgePayloadMarker = [Text.Encoding]::ASCII.GetBytes('JGTFUVQ`TUBSU')

function Test-InstallForgeBooleanValue {
  <#
  .SYNOPSIS
    Interpret Boolean values emitted by InstallForge configuration files.
  .PARAMETER Value
    Configuration value to interpret.
  .PARAMETER Default
    Result for absent or unrecognized values.
  #>
  [OutputType([bool])]
  param ([AllowNull()][object]$Value, [bool]$Default = $false)

  if ($null -eq $Value) { return $Default }
  switch -Regex ([string]$Value) {
    '^(?i:1|true|yes|on)$' { return $true }
    '^(?i:0|false|no|off)$' { return $false }
    default { return $Default }
  }
}

function Test-InstallForgeResolvedValue {
  <#
  .SYNOPSIS
    Test whether a compiled value contains no unresolved InstallForge variables.
  .PARAMETER Value
    Compiled or partially resolved value. Null is accepted.
  #>
  [OutputType([bool])]
  param ([AllowNull()][string]$Value)

  return $null -eq $Value -or ($Value -notmatch '<[^<>]+>' -and $Value -notmatch '\[[^\[\]]+\]')
}

function Get-InstallForgeUnresolvedPropertyName {
  <#
  .SYNOPSIS
    Identify record properties that still contain runtime-only InstallForge expressions.
  .PARAMETER InputObject
    Parsed command, shortcut, or finish-action record after deterministic constants have been resolved.
  .PARAMETER PropertyName
    Text properties to inspect for unresolved angle-bracket or bracket expressions.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][psobject]$InputObject,
    [Parameter(Mandatory)][string[]]$PropertyName
  )

  $Result = [Collections.Generic.List[string]]::new()
  foreach ($Name in $PropertyName) {
    if ($InputObject.PSObject.Properties[$Name] -and -not (Test-InstallForgeResolvedValue -Value ([string]$InputObject.$Name))) { $Result.Add($Name) }
  }
  return $Result.ToArray()
}

function ConvertTo-InstallForgeRegistryHive {
  <#
  .SYNOPSIS
    Normalize InstallForge registry-root names to canonical short hive names.
  .PARAMETER Root
    Compiled registry root such as HKEY_LOCAL_MACHINE or HKLM.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Root)

  switch -Regex ($Root) {
    '^(?i:HKEY_LOCAL_MACHINE|HKLM)$' { return 'HKLM' }
    '^(?i:HKEY_CURRENT_USER|HKCU)$' { return 'HKCU' }
    '^(?i:HKEY_CLASSES_ROOT|HKCR)$' { return 'HKCR' }
    '^(?i:HKEY_USERS|HKU)$' { return 'HKU' }
    '^(?i:HKEY_CURRENT_CONFIG|HKCC)$' { return 'HKCC' }
    default { return $Root }
  }
}

function ConvertFrom-InstallForgeEncodedPathSegment {
  <#
  .SYNOPSIS
    Decode one canonical Base64 UTF-16LE path segment used by the 1.4+ engine.
  .PARAMETER Segment
    One archive path segment. Ordinary names are returned unchanged.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Segment)

  if ($Segment -ieq 'empty.empty' -or $Segment -notmatch '^[A-Za-z0-9+/]+={0,2}$' -or ($Segment.Length % 4) -ne 0) { return $Segment }
  try {
    $Bytes = [Convert]::FromBase64String($Segment)
    if ($Bytes.Length -eq 0 -or ($Bytes.Length % 2) -ne 0) { return $Segment }
    $Decoded = [Text.Encoding]::Unicode.GetString($Bytes).TrimEnd([char]0)
    if ([string]::IsNullOrWhiteSpace($Decoded) -or $Decoded.IndexOf([char]0) -ge 0 -or $Decoded.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { return $Segment }
    $WithTerminator = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Decoded + [char]0))
    $WithoutTerminator = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Decoded))
    if ($Segment -cne $WithTerminator -and $Segment -cne $WithoutTerminator) { return $Segment }
    return $Decoded
  } catch {
    return $Segment
  }
}

function ConvertFrom-InstallForgeEncodedPath {
  <#
  .SYNOPSIS
    Decode every structured path segment in a modern InstallForge archive name.
  .PARAMETER Path
    Archive-relative path.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Path)

  return (($Path -split '[\\/]' | ForEach-Object { ConvertFrom-InstallForgeEncodedPathSegment -Segment $_ }) -join [IO.Path]::DirectorySeparatorChar)
}

function ConvertFrom-InstallForgeTextBytes {
  <#
  .SYNOPSIS
    Decode a bounded compiled table using BOM-aware UTF-8 and legacy Windows-1252.
  .PARAMETER Bytes
    Complete bytes of one configuration entry.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  if ($Bytes.Length -eq 0) { return '' }
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3) }
  if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) }
  if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $Bytes.Length - 2) }
  try { return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) } catch { return [Text.Encoding]::GetEncoding(1252).GetString($Bytes) }
}

function Split-InstallForgeTextLine {
  <#
  .SYNOPSIS
    Split CRLF-delimited compiled tables while preserving intentional empty fields.
  .PARAMETER Text
    Complete decoded table text.
  #>
  [OutputType([string[]])]
  param ([AllowEmptyString()][string]$Text)

  if ([string]::IsNullOrEmpty($Text)) { return [string[]]@() }
  $Lines = [Collections.Generic.List[string]]::new([regex]::Split($Text, "`r`n|`n|`r"))
  # Splitting a table terminated by a line break creates one synthetic final
  # element. Remove only that terminator; preceding empty strings are fields.
  if ($Lines.Count -gt 0 -and $Lines[$Lines.Count - 1] -eq '' -and $Text -match "(?:`r`n|`n|`r)$") { $Lines.RemoveAt($Lines.Count - 1) }
  return $Lines.ToArray()
}

function Read-InstallForgeByteLine {
  <#
  .SYNOPSIS
    Read one CRLF-terminated text field from a mixed text/binary table.
  .PARAMETER Bytes
    Complete table bytes.
  .PARAMETER Position
    Caller-owned byte cursor updated to the first byte after CRLF.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Position
  )

  $Start = [int]$Position.Value
  for ($Index = $Start; $Index -lt $Bytes.Length - 1; $Index++) {
    if ($Bytes[$Index] -eq 0x0D -and $Bytes[$Index + 1] -eq 0x0A) {
      $Length = $Index - $Start
      $Field = $Length -eq 0 ? '' : (ConvertFrom-InstallForgeTextBytes -Bytes $Bytes[$Start..($Index - 1)])
      $Position.Value = $Index + 2
      return $Field
    }
  }
  throw 'An InstallForge table text field is not terminated by CRLF.'
}

function Read-InstallForgeArchiveEntries {
  <#
  .SYNOPSIS
    Materialize one bounded configuration archive into an in-memory entry map.
  .PARAMETER Archive
    Open shared archive object owned by the caller.
  .PARAMETER DecodeNames
    Decode modern Base64 UTF-16LE names.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$Archive, [switch]$DecodeNames)

  $Entries = [Collections.Generic.List[object]]::new()
  $Content = [ordered]@{}
  [long]$TotalBytes = 0
  foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
    if ($Entries.Count -ge $Script:InstallForgeMaximumEntries) { throw 'The InstallForge configuration exceeds the entry-count limit.' }
    if ($Entry.Length -gt $Script:InstallForgeMaximumEntryBytes -or $Entry.Length -gt $Script:InstallForgeMaximumConfigurationBytes - $TotalBytes) { throw 'The InstallForge configuration exceeds the configured byte limit.' }
    $Name = $DecodeNames ? (ConvertFrom-InstallForgeEncodedPath -Path $Entry.FullName) : $Entry.FullName.Replace('/', '\').TrimStart('\')
    if ([string]::IsNullOrWhiteSpace($Name) -or $Content.Contains($Name)) { throw "The InstallForge configuration contains a duplicate or empty entry '$Name'." }
    $Bytes = $Entry.Length -eq 0 ? [byte[]]::new(0) : (Read-InstallerArchiveEntryBytes -Entry $Entry -MaximumBytes ([int]$Script:InstallForgeMaximumEntryBytes))
    $TotalBytes += $Bytes.Length
    $Content[$Name] = $Bytes
    $Entries.Add([pscustomobject]@{ FullName = $Name; EncodedName = $Entry.FullName; Length = [long]$Bytes.Length })
  }
  if (-not $Content.Contains('SC.dat')) { throw 'The InstallForge configuration archive does not contain SC.dat.' }
  return [pscustomobject]@{ Entries = $Entries.ToArray(); Content = $Content; ExpandedBytes = $TotalBytes }
}

function Get-InstallForgeModernConfiguration {
  <#
  .SYNOPSIS
    Read the named resource archive used by the native 1.4+ setup engine.
  .PARAMETER Path
    Resolved installer path.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $Resource = Get-PEResourceInfo -Path $Path | Where-Object { $_.TypeId -eq 10 -and $_.Name -ieq 'SETUPCONFIGURATION' } | Select-Object -First 1
  if (-not $Resource) { return $null }
  if ($Resource.Size -le 0 -or $Resource.Size -gt $Script:InstallForgeMaximumConfigurationBytes) { throw 'The InstallForge SETUPCONFIGURATION resource exceeds the configured size limit.' }
  $TemporaryPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallForge-$([guid]::NewGuid().ToString('N')).7z")
  try {
    $null = Export-PEResourceData -Resource $Resource -DestinationPath $TemporaryPath -MaximumBytes $Script:InstallForgeMaximumConfigurationBytes
    $Archive = Get-InstallerArchive -Path $TemporaryPath
    try { $Data = Read-InstallForgeArchiveEntries -Archive $Archive -DecodeNames } finally { $Archive.Dispose() }
    return [pscustomobject]@{ Generation = 'Modern'; ContainerRoute = 'Resource7z'; Resource = $Resource; Entries = $Data.Entries; Content = $Data.Content; CabinetRange = $null }
  } finally {
    Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
  }
}

function Open-InstallForgeGZipTarPayload {
  <#
  .SYNOPSIS
    Open the bounded GZip and TAR layers used by InstallForge 1.4.x payloads.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Offset
    Absolute offset of the GZip member.
  .PARAMETER Length
    Maximum compressed range, excluding a trailing PE certificate when present.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][long]$Length
  )

  $Source = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Range = New-BoundedReadStream -Stream $Source -Offset $Offset -Length $Length -LeaveOpen
    try {
      $Decoder = [IO.Compression.GZipStream]::new($Range, [IO.Compression.CompressionMode]::Decompress, $false)
      try {
        $Reader = [Formats.Tar.TarReader]::new($Decoder, $false)
        return [pscustomobject]@{ Source = $Source; Range = $Range; Decoder = $Decoder; Reader = $Reader }
      } catch {
        $Decoder.Dispose()
        throw
      }
    } catch {
      $Range.Dispose()
      throw
    }
  } catch {
    $Source.Dispose()
    throw
  }
}

function Close-InstallForgeGZipTarPayload {
  <#
  .SYNOPSIS
    Dispose every stream owned by an InstallForge GZip/TAR context.
  .PARAMETER Context
    Context returned by Open-InstallForgeGZipTarPayload.
  #>
  param ([AllowNull()][psobject]$Context)

  if (-not $Context) { return }
  try { $Context.Reader.Dispose() } catch {}
  try { $Context.Decoder.Dispose() } catch {}
  try { $Context.Range.Dispose() } catch {}
  try { $Context.Source.Dispose() } catch {}
}

function Test-InstallForgeGZipIntegrity {
  <#
  .SYNOPSIS
    Validate the GZip trailer CRC32 and modulo-32-bit uncompressed size.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Offset
    Absolute offset of the GZip member.
  .PARAMETER Length
    Maximum bounded GZip range, excluding a trailing PE certificate.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][long]$Length
  )

  if ($Length -lt 18) { throw 'The InstallForge GZip payload is shorter than a complete member.' }
  $Source = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Range = New-BoundedReadStream -Stream $Source -Offset $Offset -Length $Length -LeaveOpen
    try {
      $Decoder = [IO.Compression.GZipStream]::new($Range, [IO.Compression.CompressionMode]::Decompress, $false)
      try {
        $Actual = [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32WithLength($Decoder, $false, $Script:InstallForgeMaximumExpandedBytes, $null)
      } finally {
        $Decoder.Dispose()
      }
    } finally {
      $Range.Dispose()
    }
    $ActualSize = [uint32]($Actual.Length % 4294967296L)
    $Trailer = [byte[]]::new(8)
    [BitConverter]::GetBytes([uint32]$Actual.Checksum).CopyTo($Trailer, 0)
    [BitConverter]::GetBytes($ActualSize).CopyTo($Trailer, 4)
    $TrailerOffset = @(Find-BinaryPattern -Stream $Source -Pattern $Trailer -StartOffset $Offset -Length $Length -Maximum 1 -Reverse)
    if ($TrailerOffset.Count -ne 1) { throw 'The InstallForge GZip payload has no trailer matching its calculated CRC32 and ISIZE.' }
    return [pscustomobject]@{ Crc32 = [uint32]$Actual.Checksum; ExpandedSize = [long]$Actual.Length; TrailerOffset = [long]$TrailerOffset[0]; MemberLength = [long]($TrailerOffset[0] + 8 - $Offset) }
  } finally {
    $Source.Dispose()
  }
}

function Get-InstallForgeGZipTarPayloadData {
  <#
  .SYNOPSIS
    Validate and catalog the encoded TAR payload used by InstallForge 1.4.x.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Offset
    Absolute offset of the GZip member.
  .PARAMETER Length
    Bounded compressed range.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][long]$Length
  )

  $Integrity = Test-InstallForgeGZipIntegrity -Path $Path -Offset $Offset -Length $Length
  $Length = $Integrity.MemberLength
  $Context = Open-InstallForgeGZipTarPayload -Path $Path -Offset $Offset -Length $Length
  try {
    $Entries = [Collections.Generic.List[object]]::new()
    $Paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [long]$ExpandedBytes = 0
    $HasEncodedName = $false
    while ($Entry = $Context.Reader.GetNextEntry($false)) {
      if ($Entry.EntryType -eq [Formats.Tar.TarEntryType]::Directory) { continue }
      if ($Entry.EntryType -notin [Formats.Tar.TarEntryType]::RegularFile, [Formats.Tar.TarEntryType]::V7RegularFile, [Formats.Tar.TarEntryType]::ContiguousFile) {
        throw "The InstallForge TAR payload contains unsupported entry type '$($Entry.EntryType)'."
      }
      if ($Entries.Count -ge $Script:InstallForgeMaximumEntries) { throw 'The InstallForge payload exceeds the entry-count limit.' }
      if ($Entry.Length -lt 0 -or $Entry.Length -gt $Script:InstallForgeMaximumEntryBytes) { throw "The InstallForge payload entry '$($Entry.Name)' exceeds the per-entry limit." }
      if ($Entry.Length -gt $Script:InstallForgeMaximumExpandedBytes - $ExpandedBytes) { throw 'The InstallForge payload exceeds the aggregate expanded-byte limit.' }
      $Name = ConvertFrom-InstallForgeEncodedPath -Path $Entry.Name
      if ([string]::IsNullOrWhiteSpace($Name) -or -not $Paths.Add($Name)) { throw "The InstallForge TAR payload contains a duplicate or empty decoded path '$Name'." }
      $null = Resolve-SafeExtractionPath -DestinationPath ([IO.Path]::GetTempPath()) -RelativePath $Name
      $HasEncodedName = $HasEncodedName -or $Name -cne $Entry.Name
      $ExpandedBytes += $Entry.Length
      $Entries.Add([pscustomobject]@{ FullName = $Name; EncodedName = $Entry.Name; Length = [long]$Entry.Length; CompressedSize = $null; EntryType = [string]$Entry.EntryType })
    }
    if ($Entries.Count -eq 0 -or -not $HasEncodedName) { throw 'The GZip/TAR range does not contain a canonical InstallForge payload catalog.' }
    return [pscustomobject]@{ SourcePath = $Path; Range = [pscustomobject]@{ Offset = $Offset; Length = $Length }; Entries = $Entries.ToArray(); Format = 'GZipTar'; Route = 'OverlayGZipTar'; Offset = $Offset; Length = $Length; ExpandedBytes = $ExpandedBytes; GZipIntegrity = $Integrity }
  } finally {
    Close-InstallForgeGZipTarPayload -Context $Context
  }
}

function Get-InstallForgeLegacyConfiguration {
  <#
  .SYNOPSIS
    Read the CAB configuration appended by the 1.2.x-1.3.x setup engine.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER OverlayOffset
    Absolute start of the PE overlay.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][long]$OverlayOffset)

  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern ([Text.Encoding]::ASCII.GetBytes('MSCF')) -StartOffset $OverlayOffset -Maximum 16)) {
      if ($Offset -gt $OverlayOffset + 1MB -or $Offset + 12 -gt $Stream.Length) { continue }
      $CabinetLength = [long](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 8) -Size 4 -Endian LittleEndian)
      if ($CabinetLength -lt 36 -or $CabinetLength -gt $Script:InstallForgeMaximumConfigurationBytes -or $CabinetLength -gt $Stream.Length - $Offset) { continue }
      $TemporaryPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallForge-$([guid]::NewGuid().ToString('N')).cab")
      $Destination = [IO.File]::Open($TemporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { Copy-BinaryStreamRange -Source $Stream -Destination $Destination -Offset $Offset -Length $CabinetLength } finally { $Destination.Dispose() }
      try {
        try { $CabinetEntries = @(Get-CabinetEntry -Path $TemporaryPath -MaximumEntries $Script:InstallForgeMaximumEntries) } catch { continue }
        if (-not ($CabinetEntries | Where-Object FullName -IEQ 'SC.dat')) { continue }
        $Content = [ordered]@{}
        $Entries = [Collections.Generic.List[object]]::new()
        $StagingPath = New-TempFolder
        try {
          $Selection = [Collections.Generic.List[object]]::new()
          foreach ($Entry in $CabinetEntries) {
            if ($Entry.Length -gt $Script:InstallForgeMaximumEntryBytes) { throw "The InstallForge configuration entry '$($Entry.FullName)' exceeds the configured size limit." }
            $Target = Join-Path $StagingPath ('entry-{0:D8}.bin' -f $Selection.Count)
            $Selection.Add([pscustomobject]@{ SourceName = $Entry.SourceName; DestinationPath = $Target; Length = $Entry.Length; Name = $Entry.FullName })
          }
          $null = Export-CabinetSelection -Path $TemporaryPath -Selection $Selection.ToArray() -MaximumEntries $Script:InstallForgeMaximumEntries -MaximumExpandedBytes $Script:InstallForgeMaximumConfigurationBytes
          foreach ($Item in $Selection) {
            $EntryStream = [IO.File]::Open($Item.DestinationPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try { $Bytes = Read-BinaryBytes -Stream $EntryStream -Offset 0 -Count ([int]$EntryStream.Length) } finally { $EntryStream.Dispose() }
            $Content[$Item.Name] = $Bytes
            $Entries.Add([pscustomobject]@{ FullName = $Item.Name; EncodedName = $Item.Name; Length = [long]$Bytes.Length })
          }
        } finally {
          Remove-Item -LiteralPath $StagingPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        return [pscustomobject]@{ Generation = 'Legacy'; ContainerRoute = 'CabinetZip'; Resource = $null; Entries = $Entries.ToArray(); Content = $Content; CabinetRange = [pscustomobject]@{ Offset = [long]$Offset; Length = $CabinetLength } }
      } finally {
        Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
      }
    }
  } finally {
    $Stream.Dispose()
  }
  return $null
}

function Get-InstallForgePayloadData {
  <#
  .SYNOPSIS
    Select and catalog the payload archive associated with a validated configuration.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Generation
    Legacy or Modern configuration generation.
  .PARAMETER OverlayOffset
    Absolute PE overlay offset.
  .PARAMETER CabinetRange
    Legacy configuration CAB range used to bound ZIP selection.
  .PARAMETER LogicalEnd
    Absolute end of installer-owned data, excluding a trailing PE certificate.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidateSet('Legacy', 'Modern')][string]$Generation,
    [Parameter(Mandatory)][long]$OverlayOffset,
    [AllowNull()][psobject]$CabinetRange,
    [Parameter(Mandatory)][long]$LogicalEnd
  )

  $Ranges = $null
  if ($Generation -eq 'Modern' -and $LogicalEnd -ge $OverlayOffset + 23) {
    $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Marker = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count $Script:InstallForgePayloadMarker.Length
      if (Test-BinarySequence -Left $Marker -Right $Script:InstallForgePayloadMarker) {
        $DataOffset = $OverlayOffset + 21
        $Signature = Read-BinaryBytes -Stream $Stream -Offset $DataOffset -Count 6
        if ($Signature[0] -eq 0x1F -and $Signature[1] -eq 0x8B) {
          return Get-InstallForgeGZipTarPayloadData -Path $Path -Offset $DataOffset -Length ($LogicalEnd - $DataOffset)
        }
        if (Test-BinarySequence -Left $Signature -Right ([byte[]](0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))) {
          $Ranges = @(Get-EmbeddedSevenZipArchiveRange -Path $Path -StartOffset $DataOffset -MaximumArchives 1 -MaximumArchiveBytes $Script:InstallForgeMaximumArchiveBytes | Where-Object Offset -EQ $DataOffset)
        } else {
          throw 'The InstallForge payload marker is followed by an unsupported compression signature.'
        }
      }
    } finally {
      $Stream.Dispose()
    }
  }

  if ($null -eq $Ranges) {
    $Ranges = if ($Generation -eq 'Legacy') {
      $MinimumOffset = $CabinetRange.Offset + $CabinetRange.Length
      @(Get-EmbeddedZipArchiveRange -Path $Path -MaximumArchives 16 | Where-Object Offset -GE $MinimumOffset)
    } else {
      @(Get-EmbeddedSevenZipArchiveRange -Path $Path -StartOffset $OverlayOffset -MaximumArchives 16 -MaximumArchiveBytes $Script:InstallForgeMaximumArchiveBytes)
    }
  }
  foreach ($Range in $Ranges) {
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $Path -Range $Range
      $Entries = [Collections.Generic.List[object]]::new()
      $Paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      [long]$ExpandedBytes = 0
      foreach ($Entry in Get-InstallerArchiveEntry -Archive $Context.Archive) {
        if ($Entries.Count -ge $Script:InstallForgeMaximumEntries) { throw 'The InstallForge payload exceeds the entry-count limit.' }
        if ($Entry.Length -lt 0 -or $Entry.Length -gt $Script:InstallForgeMaximumEntryBytes) { throw "The InstallForge payload entry '$($Entry.FullName)' exceeds the per-entry limit." }
        if ($Entry.Length -gt $Script:InstallForgeMaximumExpandedBytes - $ExpandedBytes) { throw 'The InstallForge payload exceeds the aggregate expanded-byte limit.' }
        $Name = $Generation -eq 'Modern' ? (ConvertFrom-InstallForgeEncodedPath -Path $Entry.FullName) : $Entry.FullName.Replace('/', '\').TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($Name)) { continue }
        if (-not $Paths.Add($Name)) { throw "The InstallForge payload contains duplicate decoded path '$Name'." }
        $null = Resolve-SafeExtractionPath -DestinationPath ([IO.Path]::GetTempPath()) -RelativePath $Name
        $ExpandedBytes += $Entry.Length
        $Entries.Add([pscustomobject]@{ FullName = $Name; EncodedName = $Entry.FullName; Length = [long]$Entry.Length; CompressedSize = [long]$Entry.CompressedSize })
      }
      if ($Entries.Count -eq 0) { continue }
      if ($Generation -eq 'Modern' -and -not ($Entries | Where-Object { $_.EncodedName -cne $_.FullName } | Select-Object -First 1)) { continue }
      return [pscustomobject]@{ SourcePath = $Path; Range = $Range; Entries = $Entries.ToArray(); Format = $Generation -eq 'Legacy' ? 'ZIP' : '7z'; Route = $Generation -eq 'Legacy' ? 'OverlayZip' : 'Overlay7z'; Offset = [long]$Range.Offset; Length = [long]$Range.Length; ExpandedBytes = $ExpandedBytes }
    } catch {
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }
  return $null
}

function Get-InstallForgeLayout {
  <#
  .SYNOPSIS
    Parse the physical configuration and payload routes once for one installer.
  .PARAMETER Path
    Installer path. PowerShell-relative paths are resolved before managed access.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $PELayout = Get-PELayout -Path $File.FullName
  if (-not $PELayout) { throw 'The file is not a valid PE image.' }
  $OverlayOffset = Get-PEOverlayOffset -Path $File.FullName
  if ($OverlayOffset -le 0 -or $OverlayOffset -ge $File.Length) { throw 'The InstallForge candidate has no bounded PE overlay.' }
  $Certificate = $PELayout.DataDirectories['Certificate']
  $LogicalEnd = if ($Certificate -and $Certificate.Offset -gt $OverlayOffset -and $Certificate.Offset -le $File.Length) { [long]$Certificate.Offset } else { [long]$File.Length }
  $Configuration = Get-InstallForgeModernConfiguration -Path $File.FullName
  if (-not $Configuration) { $Configuration = Get-InstallForgeLegacyConfiguration -Path $File.FullName -OverlayOffset $OverlayOffset }
  if (-not $Configuration) { throw 'The PE contains neither a valid InstallForge SETUPCONFIGURATION resource nor a legacy configuration cabinet.' }
  $Payload = Get-InstallForgePayloadData -Path $File.FullName -Generation $Configuration.Generation -OverlayOffset $OverlayOffset -CabinetRange $Configuration.CabinetRange -LogicalEnd $LogicalEnd
  return [pscustomobject]@{ Path = $File.FullName; Length = [long]$File.Length; OverlayOffset = [long]$OverlayOffset; LogicalEnd = $LogicalEnd; Generation = $Configuration.Generation; ContainerRoute = $Configuration.ContainerRoute; PayloadRoute = $Payload ? $Payload.Route : $null; Configuration = $Configuration; Payload = $Payload }
}

function Get-InstallForgeConfigurationText {
  <#
  .SYNOPSIS
    Read one previously materialized configuration table as text.
  .PARAMETER Layout
    Validated InstallForge layout.
  .PARAMETER Name
    Exact configuration entry name.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][psobject]$Layout, [Parameter(Mandatory)][string]$Name)

  if (-not $Layout.Configuration.Content.Contains($Name)) { return $null }
  return ConvertFrom-InstallForgeTextBytes -Bytes $Layout.Configuration.Content[$Name]
}

function ConvertFrom-InstallForgeFixedRecordTable {
  <#
  .SYNOPSIS
    Decode a CRLF table containing a fixed number of text fields per record.
  .PARAMETER Text
    Decoded table text.
  .PARAMETER FieldName
    Field names in compiled order.
  .PARAMETER Source
    Configuration entry name retained as evidence.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string[]]$FieldName, [Parameter(Mandatory)][string]$Source)

  $Lines = @(Split-InstallForgeTextLine -Text $Text)
  if ($Lines.Count -eq 0) { return @() }
  if (($Lines.Count % $FieldName.Count) -ne 0) { throw "$Source contains an incomplete $($FieldName.Count)-field record." }
  $Result = [Collections.Generic.List[object]]::new()
  for ($Offset = 0; $Offset -lt $Lines.Count; $Offset += $FieldName.Count) {
    $Record = [ordered]@{ Source = $Source; Index = [int]($Offset / $FieldName.Count) }
    for ($Index = 0; $Index -lt $FieldName.Count; $Index++) { $Record[$FieldName[$Index]] = $Lines[$Offset + $Index] }
    $Result.Add([pscustomobject]$Record)
  }
  return $Result.ToArray()
}

function ConvertFrom-InstallForgeRegistryTable {
  <#
  .SYNOPSIS
    Decode Registry.dat four-line records followed by UInt32 LE flags.
  .PARAMETER Bytes
    Complete Registry.dat bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  if ($Bytes.Length -eq 0) { return @() }
  $Result = [Collections.Generic.List[object]]::new()
  $Position = 0
  while ($Position -lt $Bytes.Length) {
    if ($Result.Count -ge $Script:InstallForgeMaximumEntries) { throw 'Registry.dat exceeds the record-count limit.' }
    $Cursor = [ref]$Position
    $Root = Read-InstallForgeByteLine -Bytes $Bytes -Position $Cursor
    $Key = Read-InstallForgeByteLine -Bytes $Bytes -Position $Cursor
    $Name = Read-InstallForgeByteLine -Bytes $Bytes -Position $Cursor
    $Value = Read-InstallForgeByteLine -Bytes $Bytes -Position $Cursor
    $Position = $Cursor.Value
    if ($Position + 4 -gt $Bytes.Length) { throw 'Registry.dat ends before its UInt32 removal flag.' }
    $RemoveOnUninstall = [BitConverter]::ToUInt32($Bytes, $Position) -ne 0
    $Position += 4
    $Result.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $Name; Value = $Value; Type = 'String'; RemoveOnUninstall = $RemoveOnUninstall; Source = 'Registry.dat'; Index = $Result.Count })
  }
  return $Result.ToArray()
}

function Get-InstallForgeConstantMap {
  <#
  .SYNOPSIS
    Build the deterministic constant map used by compiled InstallForge records.
  .PARAMETER Setup
    Parsed Setup section.
  #>
  [OutputType([Collections.IDictionary])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Setup)

  $Map = [ordered]@{
    AppName               = [string](Get-DictionaryValue -Dictionary $Setup -Name Appname)
    AppVersion            = [string](Get-DictionaryValue -Dictionary $Setup -Name Version)
    Company               = [string](Get-DictionaryValue -Dictionary $Setup -Name Company)
    ProgramFiles          = '%ProgramFiles(x86)%'
    ProgramFilesX86       = '%ProgramFiles(x86)%'
    ProgramFilesX64       = '%ProgramFiles%'
    CommonFiles           = '%CommonProgramFiles(x86)%'
    CommonProgramFiles    = '%CommonProgramFiles(x86)%'
    CommonProgramFilesX86 = '%CommonProgramFiles(x86)%'
    CommonApplicationData = '%ProgramData%'
    CommonDesktop         = '%PUBLIC%\Desktop'
    CommonDocuments       = '%PUBLIC%\Documents'
    CommonPrograms        = '%ProgramData%\Microsoft\Windows\Start Menu\Programs'
    CommonStartMenu       = '%ProgramData%\Microsoft\Windows\Start Menu'
    CommonStartup         = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'
    AppData               = '%APPDATA%'
    ApplicationData       = '%APPDATA%'
    LocalAppData          = '%LOCALAPPDATA%'
    LocalApplicationData  = '%LOCALAPPDATA%'
    UserProfile           = '%USERPROFILE%'
    Desktop               = '%USERPROFILE%\Desktop'
    Documents             = '%USERPROFILE%\Documents'
    MyDocuments           = '%USERPROFILE%\Documents'
    MyMusic               = '%USERPROFILE%\Music'
    MyPictures            = '%USERPROFILE%\Pictures'
    MyVideos              = '%USERPROFILE%\Videos'
    Programs              = '%APPDATA%\Microsoft\Windows\Start Menu\Programs'
    StartMenu             = '%APPDATA%\Microsoft\Windows\Start Menu'
    Startup               = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'
    Windows               = '%WINDIR%'
    System                = '%WINDIR%\System32'
    SystemX86             = '%WINDIR%\SysWOW64'
    Fonts                 = '%WINDIR%\Fonts'
  }
  $InstallDir = [string](Get-DictionaryValue -Dictionary $Setup -Name InstallDir)
  for ($Pass = 0; $Pass -lt 8; $Pass++) {
    $Previous = $InstallDir
    foreach ($Key in @($Map.Keys)) {
      $InstallDir = $InstallDir -replace "(?i)<$([regex]::Escape([string]$Key))>", [string]$Map[$Key]
      $InstallDir = $InstallDir -replace "(?i)\[$([regex]::Escape([string]$Key))\]", [string]$Map[$Key]
    }
    if ($InstallDir -ceq $Previous) { break }
  }
  $Map.InstallPath = $InstallDir.TrimEnd('\')
  return $Map
}

function Resolve-InstallForgeConstantValue {
  <#
  .SYNOPSIS
    Resolve only deterministic angle-bracket constants in one compiled value.
  .PARAMETER Value
    Compiled text value.
  .PARAMETER Constant
    Deterministic constant map.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Value, [Parameter(Mandatory)][Collections.IDictionary]$Constant)

  if ($null -eq $Value) { return $null }
  $Resolved = $Value
  for ($Pass = 0; $Pass -lt 8; $Pass++) {
    $Previous = $Resolved
    foreach ($Key in @($Constant.Keys)) {
      $Resolved = $Resolved -replace "(?i)<$([regex]::Escape([string]$Key))>", [string]$Constant[$Key]
      $Resolved = $Resolved -replace "(?i)\[$([regex]::Escape([string]$Key))\]", [string]$Constant[$Key]
    }
    if ($Resolved -ceq $Previous) { break }
  }
  return $Resolved
}

function Get-InstallForgeShortcutRecords {
  <#
  .SYNOPSIS
    Decode generation-specific Desktop.dat and Startmenu.dat shortcut records.
  .PARAMETER Layout
    Validated InstallForge layout.
  .PARAMETER Setup
    Compiled Setup section containing the SFA and DFA all-users policies.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup
  )

  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Name in 'Desktop.dat', 'Startmenu.dat') {
    $Text = Get-InstallForgeConfigurationText -Layout $Layout -Name $Name
    if ([string]::IsNullOrEmpty($Text)) { continue }
    $Lines = @(Split-InstallForgeTextLine -Text $Text)
    $FieldNames = if ($Layout.Generation -eq 'Modern' -or ($Lines.Count % 5) -eq 0) { @('Target', 'Name', 'Arguments', 'IconPath', 'IconIndex') } elseif (($Lines.Count % 3) -eq 0) { @('Target', 'Name', 'Arguments') } else { @('Target', 'Name') }
    foreach ($Record in ConvertFrom-InstallForgeFixedRecordTable -Text $Text -FieldName $FieldNames -Source $Name) {
      $IsDesktop = $Name -ieq 'Desktop.dat'
      $PolicyName = $IsDesktop ? 'DFA' : 'SFA'
      $PolicyValue = Get-DictionaryValue -Dictionary $Setup -Name $PolicyName
      $AllUsers = $null -eq $PolicyValue ? $null : (Test-InstallForgeBooleanValue -Value $PolicyValue)
      $Record | Add-Member -NotePropertyName Destination -NotePropertyValue ($IsDesktop ? 'Desktop' : 'StartMenu')
      $Record | Add-Member -NotePropertyName AllUsers -NotePropertyValue $AllUsers
      $Record | Add-Member -NotePropertyName Scope -NotePropertyValue ($null -eq $AllUsers ? $null : ($AllUsers ? 'machine' : 'user'))
      $Record | Add-Member -NotePropertyName ScopeEvidence -NotePropertyValue ($null -eq $AllUsers ? $null : "Setup/$PolicyName")
      $Result.Add($Record)
    }
  }
  return $Result.ToArray()
}

function Test-InstallForgeLegacyArpRuntime {
  <#
  .SYNOPSIS
    Detect the legacy runtime code path that writes an Apps & Features row.
  .PARAMETER Layout
    Validated legacy layout. Only bytes before the PE overlay are scanned so
    payload strings and custom Registry.dat records cannot create a match.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][psobject]$Layout)

  if ($Layout.Generation -ne 'Legacy') { return $false }
  $UninstallPath = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
  foreach ($Encoding in [Text.Encoding]::ASCII, [Text.Encoding]::Unicode) {
    $PathMatch = @(Find-BinaryPattern -Path $Layout.Path -Pattern $Encoding.GetBytes($UninstallPath) -StartOffset 0 -Length $Layout.OverlayOffset -Maximum 1)
    if ($PathMatch.Count -eq 0) { continue }
    $NameMatch = @(Find-BinaryPattern -Path $Layout.Path -Pattern $Encoding.GetBytes('DisplayName') -StartOffset 0 -Length $Layout.OverlayOffset -Maximum 1)
    if ($NameMatch.Count -gt 0) { return $true }
  }
  return $false
}

function Get-InstallForgeCommandRecords {
  <#
  .SYNOPSIS
    Decode custom-command records and their documented runtime option tokens.
  .PARAMETER Layout
    Validated InstallForge layout.
  .PARAMETER Constant
    Deterministic constant map used to resolve command paths and arguments.
  .PARAMETER Diagnostics
    Parser diagnostic collection receiving unsupported types or option tokens.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][Collections.IDictionary]$Constant,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Diagnostics
  )

  $Text = Get-InstallForgeConfigurationText -Layout $Layout -Name 'Commands.dat'
  if ([string]::IsNullOrEmpty($Text)) { return @() }

  $Commands = @(ConvertFrom-InstallForgeFixedRecordTable -Text $Text -FieldName Type, Command, Arguments, Options -Source 'Commands.dat')
  foreach ($Command in $Commands) {
    $Command.Command = Resolve-InstallForgeConstantValue -Value $Command.Command -Constant $Constant
    $Command.Arguments = Resolve-InstallForgeConstantValue -Value $Command.Arguments -Constant $Constant
    $UnresolvedProperties = @(Get-InstallForgeUnresolvedPropertyName -InputObject $Command -PropertyName Command, Arguments)
    $OptionTokens = [string[]]@([regex]::Matches([string]$Command.Options, '\S+') | ForEach-Object Value)
    $UnknownOptions = [string[]]@($OptionTokens | Where-Object { $_ -ine '-wait' -and $_ -ine '-hide' })
    $Command | Add-Member -NotePropertyName OptionTokens -NotePropertyValue $OptionTokens
    $Command | Add-Member -NotePropertyName WaitForExit -NotePropertyValue ($OptionTokens -icontains '-wait')
    $Command | Add-Member -NotePropertyName Hidden -NotePropertyValue ($OptionTokens -icontains '-hide')
    $Command | Add-Member -NotePropertyName UnknownOptions -NotePropertyValue $UnknownOptions
    $Command | Add-Member -NotePropertyName HasUnresolvedRuntimeValue -NotePropertyValue ($UnresolvedProperties.Count -gt 0)
    $Command | Add-Member -NotePropertyName UnresolvedProperties -NotePropertyValue ([string[]]$UnresolvedProperties)

    if ($Command.Type -notin 'Execute Application', 'Shell Execute') {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Command.UnsupportedType' -Source InstallForge -Message "Custom command $($Command.Index) uses unsupported type '$($Command.Type)'." -Kind Unsupported -Areas Installability, Security -Evidence ([ordered]@{ Index = $Command.Index; Type = $Command.Type })))
    }
    if ($UnknownOptions.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Command.UnsupportedOption' -Source InstallForge -Message "Custom command $($Command.Index) uses unsupported option token(s): $($UnknownOptions -join ', ')." -Kind Unsupported -Areas Installability, Security -Evidence ([ordered]@{ Index = $Command.Index; Options = $UnknownOptions })))
    }
    if ($UnresolvedProperties.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Command.RuntimeValueUnresolved' -Source InstallForge -Message "Custom command $($Command.Index) depends on runtime-only value(s) in: $($UnresolvedProperties -join ', ')." -Kind Incomplete -Areas Installability, Security -Evidence ([ordered]@{ Index = $Command.Index; Properties = [string[]]$UnresolvedProperties })))
    }
  }
  return $Commands
}

function Get-InstallForgeRequirementInfo {
  <#
  .SYNOPSIS
    Decode the compiled OS.dat requirement dictionary.
  .PARAMETER Layout
    Validated InstallForge layout.
  #>
  [OutputType([Collections.IDictionary])]
  param ([Parameter(Mandatory)][psobject]$Layout)

  $Text = Get-InstallForgeConfigurationText -Layout $Layout -Name 'OS.dat'
  $Result = [ordered]@{}
  foreach ($Line in Split-InstallForgeTextLine -Text $Text) {
    if ($Line -match '^\s*(?<Name>[^=]+?)\s*=\s*(?<Value>\d+)\s*$') { $Result[$Matches.Name] = [int]$Matches.Value }
  }
  return $Result
}

function Get-InstallForgeCustomAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Project complete literal custom uninstall-key writes into ARP evidence.
  .PARAMETER RegistryWrite
    Resolved literal registry writes.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowEmptyCollection()][object[]]$RegistryWrite)

  $Candidates = [Collections.Generic.List[object]]::new()
  $Groups = @($RegistryWrite | Where-Object { $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)[^\\]+$' } | Group-Object Root, Key)
  foreach ($Group in $Groups) {
    $Writes = @($Group.Group)
    $DisplayName = @($Writes | Where-Object Name -IEQ 'DisplayName' | Select-Object -Last 1).Value
    if ([string]::IsNullOrWhiteSpace([string]$DisplayName)) { continue }
    $ProductCode = [regex]::Match([string]$Writes[0].Key, '(?i)Uninstall\\(?<Code>[^\\]+)$').Groups['Code'].Value
    $Values = @{}
    foreach ($Write in $Writes) { $Values[[string]$Write.Name] = $Write.Value }
    $RegistryHive = ConvertTo-InstallForgeRegistryHive -Root ([string]$Writes[0].Root)
    $SystemComponentWrite = $Writes | Where-Object Name -IEQ 'SystemComponent' | Select-Object -Last 1
    # InstallForge 1.6.1 Registry.dat emits REG_SZ values. Windows and WinGet
    # only treat a numeric SystemComponent value as the hidden-entry marker.
    $IsHidden = $SystemComponentWrite -and $SystemComponentWrite.Type -in 'DWord', 'QWord', 'Integer' -and [string]$SystemComponentWrite.Value -eq '1'
    $Candidates.Add([pscustomobject]@{
        ProductCode = $ProductCode; DisplayName = $DisplayName; DisplayVersion = $Values.DisplayVersion; Publisher = $Values.Publisher
        UninstallString = $Values.UninstallString; QuietUninstallString = $Values.QuietUninstallString; DisplayIcon = $Values.DisplayIcon
        InstallLocation = $Values.InstallLocation; SystemComponent = $Values.SystemComponent; RegistryHive = $RegistryHive
        SystemComponentType = $SystemComponentWrite ? $SystemComponentWrite.Type : $null
        RegistryView = $Writes[0].PSObject.Properties['RegistryView'] ? $Writes[0].RegistryView : $null
        IsVisible = -not $IsHidden; Source = 'Registry.dat'
      })
  }
  return $Candidates.ToArray()
}

function Export-InstallForgePayloadSelection {
  <#
  .SYNOPSIS
    Export a prevalidated selection from either InstallForge payload route.
  .PARAMETER Layout
    Parsed InstallForge layout containing a payload catalog.
  .PARAMETER Selection
    Objects with Entry and DestinationPath properties.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit in bytes.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Selection,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if ($Selection.Count -eq 0) { return [IO.FileInfo[]]@() }
  $Results = [Collections.Generic.List[IO.FileInfo]]::new($Selection.Count)
  [long]$Written = 0

  if ($Layout.Payload.Format -eq 'GZipTar') {
    $Targets = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($Item in $Selection) { $Targets.Add([string]$Item.Entry.EncodedName, $Item) }
    $Context = Open-InstallForgeGZipTarPayload -Path $Layout.Payload.SourcePath -Offset $Layout.Payload.Offset -Length $Layout.Payload.Length
    try {
      while ($Entry = $Context.Reader.GetNextEntry($false)) {
        if (-not $Targets.ContainsKey($Entry.Name)) { continue }
        $Item = $Targets[$Entry.Name]
        if ($Entry.Length -ne $Item.Entry.Length) { throw "The InstallForge TAR payload entry '$($Entry.Name)' changed length while reopening the archive." }
        if ($Entry.Length -gt $MaximumExpandedBytes - $Written) { throw 'InstallForge extraction exceeds the configured aggregate output limit.' }
        $Parent = [IO.Path]::GetDirectoryName($Item.DestinationPath)
        if (-not [string]::IsNullOrWhiteSpace($Parent)) { $null = [IO.Directory]::CreateDirectory($Parent) }
        $Output = [IO.File]::Open($Item.DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
          $null = Copy-BoundedStream -Source $Entry.DataStream -Destination $Output -MaximumBytes ($MaximumExpandedBytes - $Written) -ExpectedBytes $Entry.Length
        } catch {
          $Output.Dispose()
          Remove-Item -LiteralPath $Item.DestinationPath -Force -ErrorAction SilentlyContinue
          throw
        } finally {
          $Output.Dispose()
        }
        $File = Get-Item -LiteralPath $Item.DestinationPath -Force
        $Written += $File.Length
        $Results.Add($File)
        $null = $Targets.Remove($Entry.Name)
      }
    } finally {
      Close-InstallForgeGZipTarPayload -Context $Context
    }
    if ($Targets.Count -ne 0) { throw 'One or more selected InstallForge TAR payload entries could not be reopened.' }
    return $Results.ToArray()
  }

  $Context = Open-InstallerArchiveRange -Path $Layout.Payload.SourcePath -Range $Layout.Payload.Range
  try {
    $NativeEntries = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($Entry in Get-InstallerArchiveEntry -Archive $Context.Archive) { $NativeEntries[[string]$Entry.FullName] = $Entry }
    foreach ($Item in $Selection) {
      if (-not $NativeEntries.ContainsKey([string]$Item.Entry.EncodedName)) { throw "The InstallForge payload entry '$($Item.Entry.FullName)' could not be reopened." }
      if ($Item.Entry.Length -gt $MaximumExpandedBytes - $Written) { throw 'InstallForge extraction exceeds the configured aggregate output limit.' }
      $File = Export-InstallerArchiveEntry -Entry $NativeEntries[[string]$Item.Entry.EncodedName] -DestinationPath $Item.DestinationPath -MaximumBytes ($MaximumExpandedBytes - $Written) -CollisionAction Overwrite
      $Written += $File.Length
      $Results.Add($File)
    }
    return $Results.ToArray()
  } finally {
    Close-InstallerArchiveRange -Context $Context
  }
}

function Get-InstallForgePayloadEvidence {
  <#
  .SYNOPSIS
    Analyze the configured main payload executable or a bounded payload-wide fallback.
  .PARAMETER Layout
    Reusable InstallForge layout.
  .PARAMETER MainExecutable
    Deterministically resolved configured executable path.
  .PARAMETER InstallLocation
    Deterministically resolved installation root.
  .PARAMETER GeneratedUninstallerEntry
    Payload record generated by InstallForge for its uninstaller. It is excluded from application architecture and dependency evidence.
  .PARAMETER Diagnostics
    Mutable structured diagnostic list.
  .OUTPUTS
    Architecture and dependency evidence, the selection route, and every inspected payload path.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [AllowNull()][string]$MainExecutable,
    [AllowNull()][string]$InstallLocation,
    [AllowNull()][psobject]$GeneratedUninstallerEntry,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Diagnostics
  )

  $Empty = [pscustomobject]@{
    Architectures               = [string[]]@()
    ArchitectureInfo            = $null
    DependencyInfo              = $null
    CandidateEvidence           = [object[]]@()
    InspectedFiles              = [string[]]@()
    AnalysisRoute               = 'None'
    PayloadArchitectureComplete = $false
  }
  if (-not $Layout.Payload) { return $Empty }

  # Prefer the configured launch target because it identifies the application
  # rather than a helper or prerequisite. Exact relative paths take precedence;
  # basename matching exists only for older SC.dat records that omit folders.
  $ConfiguredCandidates = @()
  if (-not [string]::IsNullOrWhiteSpace($MainExecutable)) {
    $NormalizedMain = $MainExecutable.Trim().Trim('"').Replace('/', '\')
    $RelativeMain = $NormalizedMain
    if (-not [string]::IsNullOrWhiteSpace($InstallLocation)) {
      $Root = $InstallLocation.TrimEnd('\')
      if ($NormalizedMain.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase)) { $RelativeMain = $NormalizedMain.Substring($Root.Length + 1) }
    }
    $ConfiguredCandidates = @($Layout.Payload.Entries | Where-Object { $_.FullName.Replace('/', '\') -ieq $RelativeMain })
    if ($ConfiguredCandidates.Count -eq 0) {
      $FileName = [IO.Path]::GetFileName($RelativeMain)
      $ConfiguredCandidates = @($Layout.Payload.Entries | Where-Object { [IO.Path]::GetFileName($_.FullName) -ieq $FileName })
    }
    if ($null -ne $GeneratedUninstallerEntry) {
      $ConfiguredCandidates = @($ConfiguredCandidates | Where-Object { $_.FullName -ine $GeneratedUninstallerEntry.FullName })
    }
  }

  $AnalysisRoute = 'ConfiguredMain'
  if ($ConfiguredCandidates.Count -eq 1) {
    $PrimaryEntries = @($ConfiguredCandidates[0])
  } else {
    # When ProgramRun is absent or ambiguous, analyze every payload EXE within
    # the hard limits. Never sample this set: an omitted executable could be the
    # only evidence of a second architecture or runtime dependency.
    $AnalysisRoute = 'PayloadExecutables'
    $PrimaryEntries = @($Layout.Payload.Entries | Where-Object {
        [IO.Path]::GetExtension($_.FullName) -ieq '.exe' -and
        ($null -eq $GeneratedUninstallerEntry -or $_.FullName -ine $GeneratedUninstallerEntry.FullName)
      } | Sort-Object -Property FullName)
    if ($PrimaryEntries.Count -eq 0) {
      if (-not [string]::IsNullOrWhiteSpace($MainExecutable)) {
        $Reason = $ConfiguredCandidates.Count -eq 0 ? 'is not present in the payload catalog' : 'matches more than one payload entry'
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Payload.MainExecutableUnresolved' -Source InstallForge -Message "The configured main executable '$MainExecutable' $Reason, and the payload contains no fallback executable to analyze." -Kind Incomplete -Areas Metadata -AffectedFields Architecture, Dependencies))
      }
      return $Empty
    }
    $Message = [string]::IsNullOrWhiteSpace($MainExecutable) ? 'No configured main executable was found.' : "The configured main executable '$MainExecutable' did not resolve uniquely."
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Payload.ExecutableSetFallback' -Source InstallForge -Message "$Message Architecture and dependency evidence is derived from the complete bounded payload executable set." -Kind Fallback -Areas Metadata -AffectedFields Architecture, Dependencies -Evidence ([ordered]@{ CandidateCount = $PrimaryEntries.Count })))
  }

  [long]$PrimaryBytes = ($PrimaryEntries | Measure-Object -Property Length -Sum).Sum
  if ($PrimaryEntries.Count -gt $Script:InstallForgeMaximumAnalysisFiles -or $PrimaryBytes -gt $Script:InstallForgeMaximumAnalysisBytes) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Payload.AnalysisLimit' -Source InstallForge -Message "Payload analysis requires $($PrimaryEntries.Count) executable(s) and $PrimaryBytes bytes, above the $Script:InstallForgeMaximumAnalysisFiles-file or $Script:InstallForgeMaximumAnalysisBytes-byte limit." -Kind Incomplete -Areas Metadata -AffectedFields Architecture, Dependencies))
    return [pscustomobject]@{
      Architectures = [string[]]@(); ArchitectureInfo = $null; DependencyInfo = $null; CandidateEvidence = [object[]]@(); InspectedFiles = [string[]]@()
      AnalysisRoute = $AnalysisRoute; PayloadArchitectureComplete = $false
    }
  }

  # Adjacent DLL and JSON files improve AnyCPU and runtimeconfig analysis. If
  # sidecars exceed the remaining budget, retain complete executable architecture
  # evidence while explicitly marking dependency evidence as incomplete.
  $Entries = [Collections.Generic.List[object]]::new()
  $EntryNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $PrimaryEntries) {
    $Entries.Add($Entry)
    $null = $EntryNames.Add([string]$Entry.FullName)
  }
  [long]$DeclaredBytes = $PrimaryBytes
  $SidecarsTruncated = $false
  $PrimaryDirectories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $PrimaryEntries) { $null = $PrimaryDirectories.Add([IO.Path]::GetDirectoryName([string]$Entry.FullName)) }
  $Sidecars = @($Layout.Payload.Entries | Where-Object {
      $PrimaryDirectories.Contains([IO.Path]::GetDirectoryName([string]$_.FullName)) -and
      [IO.Path]::GetExtension($_.FullName) -iin '.dll', '.json'
    } | Sort-Object -Property FullName)
  foreach ($Entry in $Sidecars) {
    if (-not $EntryNames.Add([string]$Entry.FullName)) { continue }
    if ($Entries.Count -ge $Script:InstallForgeMaximumAnalysisFiles -or $Entry.Length -gt $Script:InstallForgeMaximumAnalysisBytes - $DeclaredBytes) {
      $SidecarsTruncated = $true
      continue
    }
    $Entries.Add($Entry)
    $DeclaredBytes += $Entry.Length
  }
  if ($SidecarsTruncated) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Payload.SidecarAnalysisLimit' -Source InstallForge -Message 'One or more adjacent DLL or JSON sidecars exceeded the bounded analysis budget; payload architecture remains complete but dependency evidence may be incomplete.' -Kind Incomplete -Areas Metadata -AffectedFields Dependencies))
  }

  $TemporaryRoot = New-TempFolder
  try {
    $Selection = [Collections.Generic.List[object]]::new($Entries.Count)
    $PathByName = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Entry in $Entries) {
      $DestinationPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryRoot -RelativePath $Entry.FullName
      $Selection.Add([pscustomobject]@{ Entry = $Entry; DestinationPath = $DestinationPath })
      $PathByName.Add([string]$Entry.FullName, $DestinationPath)
    }
    $null = Export-InstallForgePayloadSelection -Layout $Layout -Selection $Selection.ToArray() -MaximumExpandedBytes $Script:InstallForgeMaximumAnalysisBytes
    $CandidateEvidence = [Collections.Generic.List[object]]::new($PrimaryEntries.Count)
    foreach ($Primary in $PrimaryEntries) {
      $PrimaryPath = $PathByName[[string]$Primary.FullName]
      $Directory = [IO.Path]::GetDirectoryName([string]$Primary.FullName)
      $RelatedPaths = @($Entries | Where-Object {
          $_.FullName -ine $Primary.FullName -and [IO.Path]::GetDirectoryName([string]$_.FullName) -ieq $Directory
        } | ForEach-Object { $PathByName[[string]$_.FullName] })
      try {
        $ArchitectureInfo = Get-PEArchitectureInfo -Path $PrimaryPath -RelatedFile @($RelatedPaths | Where-Object { [IO.Path]::GetExtension($_) -ieq '.dll' })
      } catch {
        $ArchitectureInfo = $null
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Payload.ArchitectureAnalysisFailed' -Source InstallForge -Message "Payload executable '$($Primary.FullName)' could not be analyzed as PE architecture evidence: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture -Evidence ([ordered]@{ Path = $Primary.FullName })))
      }
      try {
        $DependencyInfo = Get-PEDependencyInfo -Path $PrimaryPath -RelatedFile $RelatedPaths
        foreach ($Diagnostic in @($DependencyInfo.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
      } catch {
        $DependencyInfo = $null
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Payload.DependencyAnalysisFailed' -Source InstallForge -Message "Payload executable '$($Primary.FullName)' dependency analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Dependencies -Evidence ([ordered]@{ Path = $Primary.FullName })))
      }
      $CandidateEvidence.Add([pscustomobject]@{ Path = $Primary.FullName; ArchitectureInfo = $ArchitectureInfo; DependencyInfo = $DependencyInfo })
    }

    $ArchitectureResults = @($CandidateEvidence | Where-Object ArchitectureInfo)
    $Architectures = @($ArchitectureResults.ArchitectureInfo.RecommendedWinGetArchitectures | Where-Object { $_ -in 'x86', 'x64', 'arm64' } | Sort-Object -Unique)
    $ArchitectureInfo = if ($ArchitectureResults.Count -eq 1) {
      $ArchitectureResults[0].ArchitectureInfo
    } elseif ($ArchitectureResults.Count -gt 1) {
      [pscustomobject]@{
        AnalysisRoute                  = $AnalysisRoute
        CandidateInfo                  = @($ArchitectureResults | ForEach-Object ArchitectureInfo)
        RecommendedWinGetArchitecture  = $Architectures.Count -eq 1 ? $Architectures[0] : $null
        RecommendedWinGetArchitectures = $Architectures
        SupportedArchitectures         = $Architectures
        Diagnostics                    = @(Merge-InstallerDiagnostics -Diagnostic @($ArchitectureResults.ArchitectureInfo.Diagnostics))
      }
    } else { $null }

    $DependencyResults = @($CandidateEvidence | Where-Object DependencyInfo)
    $DependencyInfo = if ($DependencyResults.Count -eq 1) {
      $DependencyResults[0].DependencyInfo
    } elseif ($DependencyResults.Count -gt 1) {
      $RecommendedDependencies = @($DependencyResults.DependencyInfo.RecommendedPackageDependencies | Group-Object { "$($_.PackageIdentifier)`0$($_.MinimumVersion)" } | ForEach-Object { $_.Group[0] } | Sort-Object -Property PackageIdentifier, MinimumVersion)
      [pscustomobject]@{
        Path                            = $null
        CheckedFiles                    = @($DependencyResults.DependencyInfo.CheckedFiles | Sort-Object -Unique)
        CheckedPEFiles                  = @($DependencyResults.DependencyInfo.CheckedPEFiles | Sort-Object -Unique)
        ImportedDlls                    = @($DependencyResults.DependencyInfo.ImportedDlls)
        DependsOnVCRedist               = $true -in @($DependencyResults.DependencyInfo.DependsOnVCRedist)
        DependsOnUcrt                   = $true -in @($DependencyResults.DependencyInfo.DependsOnUcrt)
        DependsOnVisualCRuntime         = $true -in @($DependencyResults.DependencyInfo.DependsOnVisualCRuntime)
        DependsOnDotNetRuntime          = $true -in @($DependencyResults.DependencyInfo.DependsOnDotNetRuntime)
        VCRedistImports                 = @($DependencyResults.DependencyInfo.VCRedistImports)
        UcrtImports                     = @($DependencyResults.DependencyInfo.UcrtImports)
        DotNetInfo                      = $null
        CandidateDependencyInfo         = @($DependencyResults | ForEach-Object DependencyInfo)
        RecommendedPackageDependencyIds = @($DependencyResults.DependencyInfo.RecommendedPackageDependencyIds | Sort-Object -Unique)
        RecommendedPackageDependencies  = $RecommendedDependencies
        Diagnostics                     = @(Merge-InstallerDiagnostics -Diagnostic @($DependencyResults.DependencyInfo.Diagnostics))
      }
    } else { $null }

    return [pscustomobject]@{
      Architectures = [string[]]$Architectures; ArchitectureInfo = $ArchitectureInfo; DependencyInfo = $DependencyInfo
      CandidateEvidence = $CandidateEvidence.ToArray(); InspectedFiles = [string[]]@($Entries.FullName)
      AnalysisRoute = $AnalysisRoute; PayloadArchitectureComplete = $ArchitectureResults.Count -eq $PrimaryEntries.Count
    }
  } finally {
    Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-InstallForgeInfo {
  <#
  .SYNOPSIS
    Parse InstallForge metadata, ARP behavior, operations, and payload evidence.
  .PARAMETER Path
    Path to an InstallForge setup. The parser does not execute it.
  .OUTPUTS
    One common installer-parser result with InstallForge-specific configuration and payload evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Layout = Get-InstallForgeLayout -Path $Path
    $OuterArchitecture = try { Get-PEArchitectureInfo -Path $Layout.Path } catch { $null }
    $MachineRegistryView = switch ($OuterArchitecture.NativeArchitecture) {
      'x86' { '32-bit' }
      { $_ -in 'x64', 'arm64' } { '64-bit' }
      default { $null }
    }
    $ConfigurationText = Get-InstallForgeConfigurationText -Layout $Layout -Name 'SC.dat'
    $Configuration = ConvertFrom-Ini -DuplicateKeyAction Last -IgnoreComments -Content $ConfigurationText
    $Setup = $Configuration['Setup']
    if (-not $Setup -or [string]::IsNullOrWhiteSpace([string](Get-DictionaryValue -Dictionary $Setup -Name Appname))) { throw 'InstallForge SC.dat does not contain a usable Setup/Appname value.' }

    $Diagnostics = [Collections.Generic.List[object]]::new()
    $Unresolved = [Collections.Generic.List[string]]::new()
    $VariableText = Get-InstallForgeConfigurationText -Layout $Layout -Name 'Variables.dat'
    $Variables = if ([string]::IsNullOrEmpty($VariableText)) { @() } else { @(ConvertFrom-InstallForgeFixedRecordTable -Text $VariableText -FieldName Name, Root, Key, ValueName, DefaultValue -Source 'Variables.dat') }
    # Registry-backed custom variables are runtime state. Their defaults remain
    # evidence but are not substituted into authoritative manifest fields.
    $Constant = Get-InstallForgeConstantMap -Setup $Setup

    # Registry.dat is the only compiled operation table that mixes text and
    # binary fields. Resolve deterministic constants before ARP/association use.
    $RegistryBytes = $Layout.Configuration.Content.Contains('Registry.dat') ? $Layout.Configuration.Content['Registry.dat'] : [byte[]]::new(0)
    $RegistryOperations = @(ConvertFrom-InstallForgeRegistryTable -Bytes $RegistryBytes)
    foreach ($Write in $RegistryOperations) {
      $Write.Key = Resolve-InstallForgeConstantValue -Value $Write.Key -Constant $Constant
      $Write.Name = Resolve-InstallForgeConstantValue -Value $Write.Name -Constant $Constant
      $Write.Value = Resolve-InstallForgeConstantValue -Value $Write.Value -Constant $Constant
      $RegistryHive = ConvertTo-InstallForgeRegistryHive -Root $Write.Root
      $Write | Add-Member -NotePropertyName RegistryHive -NotePropertyValue $RegistryHive
      $Write | Add-Member -NotePropertyName RegistryView -NotePropertyValue ($RegistryHive -in 'HKLM', 'HKCR' ? $MachineRegistryView : $null)
    }
    $RegistryWrites = @($RegistryOperations | Where-Object {
        (Test-InstallForgeResolvedValue -Value $_.Root) -and
        (Test-InstallForgeResolvedValue -Value $_.Key) -and
        (Test-InstallForgeResolvedValue -Value $_.Name) -and
        (Test-InstallForgeResolvedValue -Value $_.Value)
      })
    if ($RegistryWrites.Count -ne $RegistryOperations.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Registry.UnresolvedConstant' -Source InstallForge -Message 'One or more registry operations contain runtime-only or unknown constants and are excluded from association and ARP projection.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries, Protocols, FileExtensions))
    }
    $AssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Diagnostics.AddRange([object[]]$AssociationInfo.Diagnostics)

    $DisplayName = [string](Get-DictionaryValue -Dictionary $Setup -Name Appname)
    $DisplayVersion = [string](Get-DictionaryValue -Dictionary $Setup -Name Version)
    $Publisher = [string](Get-DictionaryValue -Dictionary $Setup -Name Company)
    $InstallLocationExpression = [string](Get-DictionaryValue -Dictionary $Setup -Name InstallDir)
    $InstallLocationCandidate = Resolve-InstallForgeConstantValue -Value $InstallLocationExpression -Constant $Constant
    $InstallLocation = (Test-InstallForgeResolvedValue -Value $InstallLocationCandidate) ? $InstallLocationCandidate : $null
    if (-not $InstallLocation) {
      $Unresolved.Add('DefaultInstallLocation')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Metadata.InstallLocationUnresolved' -Source InstallForge -Message 'The default installation path depends on a registry-backed or unknown runtime variable.' -Kind Incomplete -Areas Metadata -AffectedFields DefaultInstallLocation))
    }
    $WritesBuiltInArp = Test-InstallForgeBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name Uninstaller)
    $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Layout.Path
    $LegacyArpRuntime = Test-InstallForgeLegacyArpRuntime -Layout $Layout
    $UninstallerName = [string](Get-DictionaryValue -Dictionary $Setup -Name UninstallerFilename)
    if ($WritesBuiltInArp -and [string]::IsNullOrWhiteSpace($UninstallerName)) { $UninstallerName = $Layout.Generation -eq 'Legacy' ? 'Uninstall.exe' : 'Uninstall' }
    if ($WritesBuiltInArp -and $Layout.Generation -eq 'Legacy' -and -not $UninstallerName.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { $UninstallerName += '.exe' }
    $UninstallString = ($WritesBuiltInArp -and $InstallLocation) ? ((Join-Path $InstallLocation $UninstallerName).TrimEnd('\')) : $null
    $CustomIconEnabled = Test-InstallForgeBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name UninstallerUseCustomDisplayIcon)
    $DisplayIconCandidate = $CustomIconEnabled ? (Resolve-InstallForgeConstantValue -Value ([string](Get-DictionaryValue -Dictionary $Setup -Name UninstallerCustomDisplayIcon)) -Constant $Constant) : $UninstallString
    $DisplayIcon = ($WritesBuiltInArp -and (Test-InstallForgeResolvedValue -Value $DisplayIconCandidate)) ? $DisplayIconCandidate : $null
    $RegistryView = (Test-InstallForgeBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name Uninstaller_VW)) ? '64-bit' : '32-bit'

    # Controlled 1.6.1 installation proves that the native engine writes the
    # built-in ARP row to HKLM, uses Appname as its key, and omits the physical
    # .exe suffix from UninstallString when the configured name omits it.
    $BuiltInEntry = $null
    if ($WritesBuiltInArp) {
      if ($Layout.Generation -eq 'Modern') {
        $ArchiveSize = [long](Get-DictionaryValue -Dictionary $Configuration['SetupArchive'] -Name SetupArchiveFilesUncompressedSize)
        $BuiltInEntry = [pscustomobject]@{
          ProductCode = $DisplayName; DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher
          UninstallString = $UninstallString; QuietUninstallString = $null; DisplayIcon = $DisplayIcon; InstallLocation = $InstallLocation
          HelpLink = [string](Get-DictionaryValue -Dictionary $Setup -Name Website1); EstimatedSize = $ArchiveSize -gt 0 ? [long][Math]::Ceiling($ArchiveSize / 1KB) : $null
          NoModify = 1; NoRepair = 1; SystemComponent = 0; RegistryHive = 'HKLM'; RegistryView = $RegistryView; IsVisible = $true; Source = 'Built-in uninstaller configuration'
        }
      } elseif ($LegacyArpRuntime) {
        # Controlled 1.2.6.2 and 1.3.2 installations prove the legacy runtime
        # mapping. Unlike modern media, these rows omit InstallLocation, size,
        # InstallDate, NoModify, and NoRepair.
        $BuiltInEntry = [pscustomobject]@{
          ProductCode = $DisplayName; DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher
          UninstallString = $UninstallString; QuietUninstallString = $null; DisplayIcon = $UninstallString; InstallLocation = $null
          HelpLink = [string](Get-DictionaryValue -Dictionary $Setup -Name Website1); EstimatedSize = $null
          NoModify = $null; NoRepair = $null; SystemComponent = $null; RegistryHive = 'HKLM'; RegistryView = $RegistryView; IsVisible = $true; Source = 'Legacy built-in uninstaller configuration'
        }
      } else {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.ARP.LegacyRuntimeNoRegistration' -Source InstallForge -Message 'This legacy runtime packages an uninstaller but contains no built-in Apps & Features registration path; controlled 1.2.2 installation wrote no ARP key.' -Kind Information -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
      }
    }
    $CustomEntries = @(Get-InstallForgeCustomAppsAndFeaturesEntry -RegistryWrite $RegistryWrites)
    foreach ($Entry in $CustomEntries) {
      if ($Entry.SystemComponentType -eq 'String' -and [string]$Entry.SystemComponent -eq '1') {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.ARP.StringSystemComponentVisible' -Source InstallForge -Message "Custom uninstall key '$($Entry.ProductCode)' writes SystemComponent as REG_SZ; controlled WinGet enumeration confirms that the entry remains visible." -Kind Information -Areas Metadata -AffectedFields AppsAndFeaturesEntries -Evidence ([ordered]@{ ProductCode = $Entry.ProductCode; RegistryHive = $Entry.RegistryHive; RegistryView = $Entry.RegistryView; RegistryType = $Entry.SystemComponentType })))
      }
    }
    $ArpEntries = @(@($BuiltInEntry) + $CustomEntries | Where-Object { $null -ne $_ })
    $VisibleArpEntries = @($ArpEntries | Where-Object IsVisible)
    $AppsAndFeaturesEntries = @($VisibleArpEntries | ForEach-Object {
        $ManifestEntry = [ordered]@{ DisplayName = $_.DisplayName; Publisher = $_.Publisher; InstallerType = 'exe' }
        if (-not [string]::IsNullOrWhiteSpace([string]$_.DisplayVersion)) { $ManifestEntry.DisplayVersion = $_.DisplayVersion }
        if (-not [string]::IsNullOrWhiteSpace([string]$_.ProductCode)) { $ManifestEntry.ProductCode = $_.ProductCode }
        [pscustomobject]$ManifestEntry
      })
    $BuiltInManifestEntry = $null
    if ($BuiltInEntry) {
      $BuiltInManifestEntry = $AppsAndFeaturesEntries | Where-Object ProductCode -CEQ $BuiltInEntry.ProductCode | Select-Object -First 1
    }
    $ProductCode = $VisibleArpEntries.Count -eq 1 ? $VisibleArpEntries[0].ProductCode : $null
    if ($VisibleArpEntries.Count -gt 1) {
      $Unresolved.Add('ProductCode')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.ARP.MultipleVisibleEntries' -Source InstallForge -Message 'The installer defines more than one visible Apps & Features entry; no single ProductCode is selected.' -Kind Ambiguous -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
    }

    # InstallForge's built-in ARP path is machine-wide even when InstallDir uses
    # LocalAppData. Do not infer scope from destination tokens.
    $Scope = if ($WritesBuiltInArp -or $RequestedExecutionLevel -eq 'requireAdministrator') { 'machine' } elseif ($CustomEntries.Count -eq 1 -and $CustomEntries[0].RegistryHive -ieq 'HKCU') { 'user' } else { $null }
    if (-not $Scope) {
      $Unresolved.Add('Scope')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Scope.Unresolved' -Source InstallForge -Message 'The compiled artifact does not prove one installation scope.' -Kind Incomplete -Areas Metadata -AffectedFields Scope))
    }
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Installability.InteractiveOnly' -Source InstallForge -Message 'The standard InstallForge setup runtime exposes no supported unattended installation switch; /silent and /S remained interactive in controlled validation.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes))
    if (-not $Layout.Payload) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Extraction.PayloadMissing' -Source InstallForge -Message 'The configuration parsed, but no matching payload archive was found.' -Kind Incomplete -Areas Extraction -AffectedFields Architecture, Dependencies))
    }

    # Decode the remaining fixed-width tables once and retain their compiled
    # values. These records are evidence; commands are never invoked.
    $ShortcutRecords = @(Get-InstallForgeShortcutRecords -Layout $Layout -Setup $Setup)
    foreach ($Shortcut in $ShortcutRecords) {
      foreach ($Property in 'Target', 'Arguments', 'IconPath') { if ($Shortcut.PSObject.Properties[$Property]) { $Shortcut.$Property = Resolve-InstallForgeConstantValue -Value $Shortcut.$Property -Constant $Constant } }
      $ShortcutUnresolvedProperties = @(Get-InstallForgeUnresolvedPropertyName -InputObject $Shortcut -PropertyName Target, Arguments, IconPath)
      $Shortcut | Add-Member -NotePropertyName HasUnresolvedRuntimeValue -NotePropertyValue ($ShortcutUnresolvedProperties.Count -gt 0)
      $Shortcut | Add-Member -NotePropertyName UnresolvedProperties -NotePropertyValue ([string[]]$ShortcutUnresolvedProperties)
      if ($ShortcutUnresolvedProperties.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Shortcut.RuntimeValueUnresolved' -Source InstallForge -Message "$($Shortcut.Destination) shortcut $($Shortcut.Index) depends on runtime-only value(s) in: $($ShortcutUnresolvedProperties -join ', ')." -Kind Incomplete -Areas Installability -Evidence ([ordered]@{ Destination = $Shortcut.Destination; Index = $Shortcut.Index; Properties = [string[]]$ShortcutUnresolvedProperties })))
      }
    }
    $StartMenuAllUsersValue = Get-DictionaryValue -Dictionary $Setup -Name SFA
    $DesktopAllUsersValue = Get-DictionaryValue -Dictionary $Setup -Name DFA
    $StartMenuShortcutsForAllUsers = $null -eq $StartMenuAllUsersValue ? $null : (Test-InstallForgeBooleanValue -Value $StartMenuAllUsersValue)
    $DesktopShortcutsForAllUsers = $null -eq $DesktopAllUsersValue ? $null : (Test-InstallForgeBooleanValue -Value $DesktopAllUsersValue)
    $Commands = @(Get-InstallForgeCommandRecords -Layout $Layout -Constant $Constant -Diagnostics $Diagnostics)
    $Languages = @(Split-InstallForgeTextLine -Text (Get-InstallForgeConfigurationText -Layout $Layout -Name 'languages.dat'))
    $Requirements = Get-InstallForgeRequirementInfo -Layout $Layout
    $PayloadEntries = $Layout.Payload ? @($Layout.Payload.Entries | Where-Object { [IO.Path]::GetFileName($_.FullName) -ine 'empty.empty' }) : @()
    $GeneratedUninstallerEntry = $null
    if ($WritesBuiltInArp -and $PayloadEntries.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($UninstallerName)) {
      # InstallForge 1.4+ materializes the generated uninstaller as an ordinary
      # root payload record. SC.dat omits the physical .exe suffix in modern
      # media, while the payload catalog retains it.
      $GeneratedUninstallerFileName = [IO.Path]::GetFileName($UninstallerName)
      if (-not $GeneratedUninstallerFileName.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { $GeneratedUninstallerFileName += '.exe' }
      $GeneratedUninstallerCandidates = @($PayloadEntries | Where-Object { $_.FullName.Replace('/', '\').TrimStart('\') -ieq $GeneratedUninstallerFileName })
      if ($GeneratedUninstallerCandidates.Count -eq 0) {
        $GeneratedUninstallerCandidates = @($PayloadEntries | Where-Object { [IO.Path]::GetFileName($_.FullName) -ieq $GeneratedUninstallerFileName })
      }
      if ($GeneratedUninstallerCandidates.Count -eq 1) { $GeneratedUninstallerEntry = $GeneratedUninstallerCandidates[0] }
    }
    if ($WritesBuiltInArp -and -not $GeneratedUninstallerEntry) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.Extraction.UninstallerRuntimeGenerated' -Source InstallForge -Message 'The configured uninstaller is generated by the setup runtime and is not present as an independently extractable payload record.' -Kind Information -Areas Extraction -Evidence ([ordered]@{ Generation = $Layout.Generation; FileName = $UninstallerName })))
    }
    $MainExecutableExpression = [string](Get-DictionaryValue -Dictionary $Setup -Name ProgramRun)
    $MainExecutableCandidate = Resolve-InstallForgeConstantValue -Value $MainExecutableExpression -Constant $Constant
    $MainExecutable = (Test-InstallForgeResolvedValue -Value $MainExecutableCandidate) ? $MainExecutableCandidate : $null
    $PayloadEvidence = Get-InstallForgePayloadEvidence -Layout $Layout -MainExecutable $MainExecutable -InstallLocation $InstallLocation -GeneratedUninstallerEntry $GeneratedUninstallerEntry -Diagnostics $Diagnostics
    $FinishAction = [pscustomobject]@{
      Launch    = (Get-DictionaryValue -Dictionary $Setup -Name Addition) -eq '1'
      Program   = Resolve-InstallForgeConstantValue -Value ([string](Get-DictionaryValue -Dictionary $Setup -Name ProgramRun)) -Constant $Constant
      Arguments = Resolve-InstallForgeConstantValue -Value ([string](Get-DictionaryValue -Dictionary $Setup -Name ProgramRunArguments)) -Constant $Constant
    }
    $FinishActionUnresolvedProperties = @(Get-InstallForgeUnresolvedPropertyName -InputObject $FinishAction -PropertyName Program, Arguments)
    $FinishAction | Add-Member -NotePropertyName HasUnresolvedRuntimeValue -NotePropertyValue ($FinishActionUnresolvedProperties.Count -gt 0)
    $FinishAction | Add-Member -NotePropertyName UnresolvedProperties -NotePropertyValue ([string[]]$FinishActionUnresolvedProperties)
    if ($FinishAction.Launch -and $FinishActionUnresolvedProperties.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallForge.FinishAction.RuntimeValueUnresolved' -Source InstallForge -Message "The enabled finish action depends on runtime-only value(s) in: $($FinishActionUnresolvedProperties -join ', ')." -Kind Incomplete -Areas Installability, Security -Evidence ([ordered]@{ Properties = [string[]]$FinishActionUnresolvedProperties })))
    }
    # Set architecture only from a complete, single-architecture payload.
    # Leave it unresolved for mixed or partially analyzed payloads.
    $Architecture = if ($PayloadEvidence.PayloadArchitectureComplete -and $PayloadEvidence.Architectures.Count -eq 1) {
      $PayloadEvidence.Architectures[0]
    } elseif ($PayloadEvidence.AnalysisRoute -eq 'None') {
      $OuterArchitecture ? $OuterArchitecture.RecommendedWinGetArchitecture : $null
    } else { $null }

    [pscustomobject][ordered]@{
      Path = $Layout.Path; InstallerType = 'exe'; ProductCode = $ProductCode; UpgradeCode = $null
      DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher; Scope = $Scope
      DefaultInstallLocation = $InstallLocation; WritesAppsAndFeaturesEntry = $VisibleArpEntries.Count -gt 0
      AppsAndFeaturesProductCode = $ProductCode; AppsAndFeaturesInstallerType = $VisibleArpEntries.Count -gt 0 ? 'exe' : $null
      Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray()); UnresolvedFields = [string[]]@($Unresolved | Sort-Object -Unique)
      Family = 'InstallForge'; FormatGeneration = $Layout.Generation; ContainerRoute = $Layout.ContainerRoute; PayloadRoute = $Layout.PayloadRoute; LegacyArpRuntimeSupport = $Layout.Generation -eq 'Legacy' ? $LegacyArpRuntime : $null
      RequestedExecutionLevel = $RequestedExecutionLevel; ElevationRequirement = $RequestedExecutionLevel -eq 'requireAdministrator' ? 'elevationRequired' : $null
      SupportedScopes = $Scope ? @($Scope) : @(); SupportsSilentInstallation = $false; InstallerSwitches = [ordered]@{}; InstallModes = @('interactive'); InstallerSuccessCodes = @()
      PublisherUrl = [string](Get-DictionaryValue -Dictionary $Setup -Name Website1); MainExecutable = $MainExecutable; MainExecutableExpression = $MainExecutableExpression
      MainExecutableArguments = [string](Get-DictionaryValue -Dictionary $Setup -Name ProgramRunArguments); Uninstaller = $UninstallerName; UninstallString = $UninstallString; QuietUninstallString = $null; DisplayIcon = $DisplayIcon; GeneratedUninstallerEntry = $GeneratedUninstallerEntry; GeneratedUninstallerExtractable = $null -ne $GeneratedUninstallerEntry
      RegistryHive = $BuiltInEntry ? 'HKLM' : ($CustomEntries.Count -eq 1 ? $CustomEntries[0].RegistryHive : $null); RegistryView = $BuiltInEntry ? $RegistryView : ($CustomEntries.Count -eq 1 ? $CustomEntries[0].RegistryView : $null)
      AppsAndFeaturesEntries = $AppsAndFeaturesEntries; AppsAndFeaturesEvidence = $VisibleArpEntries; BuiltInAppsAndFeaturesEntry = $BuiltInManifestEntry; BuiltInAppsAndFeaturesEvidence = $BuiltInEntry; CustomAppsAndFeaturesEntries = $CustomEntries
      RegistryWrites = $RegistryWrites; RegistryOperations = $RegistryOperations; RegistryAssociationInfo = $AssociationInfo; Protocols = [string[]]$AssociationInfo.Protocols; FileExtensions = [string[]]$AssociationInfo.FileExtensions
      Shortcuts = $ShortcutRecords; StartMenuShortcutsForAllUsers = $StartMenuShortcutsForAllUsers; DesktopShortcutsForAllUsers = $DesktopShortcutsForAllUsers
      Variables = $Variables; Commands = $Commands; Requirements = $Requirements; Languages = $Languages
      FinishActions = $FinishAction
      Configuration = $Configuration; ConfigurationFiles = @($Layout.Configuration.Entries.FullName); PayloadEntries = $PayloadEntries; ExtractedFiles = [string[]]@($PayloadEntries | ForEach-Object FullName); ArchiveOffset = $Layout.Payload ? $Layout.Payload.Offset : $null; ArchiveLength = $Layout.Payload ? $Layout.Payload.Length : $null
      Architecture = $Architecture; SetupArchitectureInfo = $OuterArchitecture; PayloadArchitectures = $PayloadEvidence.Architectures; PayloadArchitectureInfo = $PayloadEvidence.ArchitectureInfo; PayloadDependencyInfo = $PayloadEvidence.DependencyInfo; DependencyInfo = $PayloadEvidence.DependencyInfo; PayloadInspectedFiles = $PayloadEvidence.InspectedFiles; PayloadAnalysisRoute = $PayloadEvidence.AnalysisRoute; PayloadArchitectureComplete = $PayloadEvidence.PayloadArchitectureComplete; PayloadCandidateEvidence = $PayloadEvidence.CandidateEvidence
      ParserVersionInfo = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallForge'; ParserMajor = 3; Sources = @('compiled SC.dat and operation tables', 'validated legacy CAB+ZIP, transitional resource-7z+GZip/TAR, or modern resource-7z+overlay-7z containers', 'controlled InstallForge 1.2.2, 1.2.6.2, 1.3.2, and 1.6.1 installed-state evidence') }
    }
  }
}

function Expand-InstallForgeInstaller {
  <#
  .SYNOPSIS
    Extract files from a validated InstallForge payload archive.
  .PARAMETER Path
    Installer path. PowerShell-relative paths are resolved before managed access.
  .PARAMETER DestinationPath
    Extraction root. A temporary folder is created when omitted.
  .PARAMETER Name
    Optional decoded path or wildcard. Omission selects all installed payload files.
  .PARAMETER CollisionAction
    Prompt, fail, skip, overwrite, or rename only when an output collision occurs.
  .PARAMETER MaximumExpandedBytes
    Aggregate extraction limit in bytes.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 16GB
  )

  process {
    $Layout = Get-InstallForgeLayout -Path $Path
    if (-not $Layout.Payload) { throw 'The InstallForge payload archive could not be located.' }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallForge-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Selection = [Collections.Generic.List[object]]::new()
    foreach ($Entry in $Layout.Payload.Entries) {
      if ([IO.Path]::GetFileName($Entry.FullName) -ieq 'empty.empty' -or -not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.FullName -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if ($Target.ShouldWrite) { $Selection.Add([pscustomobject]@{ Entry = $Entry; DestinationPath = $Target.Path }) }
    }
    if ($Selection.Count -eq 0) { throw "No InstallForge payload files matched '$Name'." }
    return Export-InstallForgePayloadSelection -Layout $Layout -Selection $Selection.ToArray() -MaximumExpandedBytes $MaximumExpandedBytes
  }
}

function Test-InstallForge {
  <#
  .SYNOPSIS
    Test for a structurally valid InstallForge configuration.
  .PARAMETER Path
    Candidate installer path.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      $Layout = Get-InstallForgeLayout -Path $Path
      $Configuration = ConvertFrom-Ini -DuplicateKeyAction Last -IgnoreComments -Content (Get-InstallForgeConfigurationText -Layout $Layout -Name 'SC.dat')
      $Setup = $Configuration['Setup']
      return $null -ne $Setup -and -not [string]::IsNullOrWhiteSpace([string](Get-DictionaryValue -Dictionary $Setup -Name Appname))
    } catch {
      return $false
    }
  }
}

function Read-ProtocolsFromInstallForge {
  <#
  .SYNOPSIS
    Read literal protocol associations.
  .PARAMETER Path
    Installer path.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallForge {
  <#
  .SYNOPSIS
    Read literal file-extension associations.
  .PARAMETER Path
    Installer path.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallForge {
  <#
  .SYNOPSIS
    Read the configured product version.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromInstallForge {
  <#
  .SYNOPSIS
    Read the configured product name.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).DisplayName }
}

function Read-PublisherFromInstallForge {
  <#
  .SYNOPSIS
    Read the configured publisher.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromInstallForge {
  <#
  .SYNOPSIS
    Read a source-backed visible uninstall-key identity.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).ProductCode }
}

function Read-ScopeFromInstallForge {
  <#
  .SYNOPSIS
    Read scope from compiled ARP and elevation evidence.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallForgeInfo, Expand-InstallForgeInstaller, Test-InstallForge, Read-ProtocolsFromInstallForge, Read-FileExtensionsFromInstallForge, Read-ProductVersionFromInstallForge, Read-ProductNameFromInstallForge, Read-PublisherFromInstallForge, Read-ProductCodeFromInstallForge, Read-ScopeFromInstallForge
