# SPDX-License-Identifier: MIT
# Static Tarma InstallMate parser. TIZ packages use raw LZMA followed by tzf3
# records. This module decodes bounded records without executing setup or
# probing arbitrary strings from payload files.
# Binary structure consumed here (LE integers unless stated otherwise):
#
#   PE overlay before certificate table
#   +-- "tiz1".."tiz4" header: version@+0x04, size@+0x10
#   +-- LZMA properties[5]@+0x38
#   `-- raw LZMA@+0x3D -> 64-byte "tzf3" segment -> "tin?" database
#
# Header and segment integers are LE. The first tzf3 segment type must be 2 and
# supplies its uint64 length at +0x10. Format-specific install-level and file
# records are read only at validated offsets under count/output limits.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallMateMaximumHeaderScanBytes = 67108864
$Script:InstallMateMinimumHeaderBytes = 61
$Script:InstallMateMaximumDatabaseBytes = 134217728
$Script:InstallMateMaximumFileRecords = 65536
$Script:InstallMateMaximumSegmentBytes = 17179869184

function Get-InstallMateScopeInfo {
  <#
  .SYNOPSIS
    Interpret InstallMate install-level behavior and PE fallback evidence
  .PARAMETER RequestedExecutionLevel
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  .PARAMETER InstallLevel
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$RequestedExecutionLevel,
    [AllowNull()][Nullable[byte]]$InstallLevel
  )

  # Structured install-level metadata is more precise than the PE manifest and
  # captures InstallMate's two elevation-dependent dual-scope modes.
  if ($null -ne $InstallLevel) {
    switch ([int]$InstallLevel) {
      0 {
        return [pscustomobject]@{
          InstallLevel = 0; InstallLevelName = 'NotChecked'; Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false
          Confidence = 'high'; Evidence = @('The structured InstallMate installer record selects Not checked, which always installs for all users without an access check.')
        }
      }
      1 {
        return [pscustomobject]@{
          InstallLevel = 1; InstallLevelName = 'CurrentUser'; Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false
          Confidence = 'high'; Evidence = @('The structured InstallMate installer record selects Current User.')
        }
      }
      2 {
        return [pscustomobject]@{
          InstallLevel = 2; InstallLevelName = 'AllUsersOrCurrentUser'; Scope = $null; DefaultScope = 'machine'; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true
          Confidence = 'high'; Evidence = @('The structured InstallMate installer record selects All Users if possible, otherwise Current User.')
        }
      }
      3 {
        return [pscustomobject]@{
          InstallLevel = 3; InstallLevelName = 'AllUsersQueryCurrentUser'; Scope = $null; DefaultScope = 'machine'; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true
          Confidence = 'high'; Evidence = @('The structured InstallMate installer record selects All Users and asks before falling back to Current User.')
        }
      }
      4 {
        return [pscustomobject]@{
          InstallLevel = 4; InstallLevelName = 'AllUsers'; Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false
          Confidence = 'high'; Evidence = @('The structured InstallMate installer record selects All Users.')
        }
      }
      5 {
        return [pscustomobject]@{
          InstallLevel = 5; InstallLevelName = 'Administrator'; Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false
          Confidence = 'high'; Evidence = @('The structured InstallMate installer record selects Administrator.')
        }
      }
    }
  }

  # Older or ambiguous databases fall back to the launcher's requested
  # execution level; this is evidence about behavior, not a registry probe.
  switch -Regex ($RequestedExecutionLevel) {
    '^(?i:requireAdministrator)$' {
      return [pscustomobject]@{
        InstallLevel = $null; InstallLevelName = $null; Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false
        Confidence = 'high'; Evidence = @('The PE requests requireAdministrator; InstallMate documents this mode as an all-users installation.')
      }
    }
    '^(?i:highestAvailable)$' {
      return [pscustomobject]@{
        InstallLevel = $null; InstallLevelName = $null; Scope = $null; DefaultScope = $null; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true
        Confidence = 'conditional'; Evidence = @('InstallMate highestAvailable installs for all users when elevated and for the current user otherwise.')
      }
    }
    '^(?i:asInvoker)$' {
      return [pscustomobject]@{
        InstallLevel = $null; InstallLevelName = $null; Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false
        Confidence = 'high'; Evidence = @('The InstallMate stub requests asInvoker, which is the Current User install level.')
      }
    }
    default {
      return [pscustomobject]@{
        InstallLevel = $null; InstallLevelName = $null; Scope = $null; DefaultScope = $null; SupportedScopes = @(); SupportsDualScope = $false
        Confidence = 'unknown'; Evidence = @('The InstallMate requested execution level could not be read.')
      }
    }
  }
}

function Read-InstallMateSequentialRecord {
  <#
  .SYNOPSIS
    Read an exact bounded InstallMate record from a sequential decoder
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Count
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Count
  )

  $Output = [IO.MemoryStream]::new($Count)
  try {
    $null = Copy-BoundedStream -Source $Stream -Destination $Output -MaximumBytes $Count -ExpectedBytes $Count
    return , ($Output.ToArray())
  } finally { $Output.Dispose() }
}

function Open-InstallMateDecoderContext {
  <#
  .SYNOPSIS
    Open one bounded raw-LZMA decoder over an InstallMate TIZ archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER ArchiveInfo
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][psobject]$ArchiveInfo
  )

  $InstallerStream = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, 'Open', 'Read', 'ReadWrite')
  $DataStream = $null
  $Decoder = $null
  try {
    # TIZ stores LZMA properties in the archive header and the raw compressed
    # stream immediately after them. The certificate table is excluded by the
    # previously validated DataEndOffset.
    $Properties = Read-BinaryBytes -Stream $InstallerStream -Offset ($ArchiveInfo.ArchiveOffset + 0x38) -Count 5
    $DataOffset = $ArchiveInfo.ArchiveOffset + 0x3D
    $CompressedSize = $ArchiveInfo.DataEndOffset - $DataOffset
    if ($CompressedSize -le 0) { throw 'The InstallMate LZMA stream is empty or truncated.' }
    $DataStream = New-BoundedReadStream -Stream $InstallerStream -Offset $DataOffset -Length $CompressedSize -LeaveOpen
    $Decoder = New-InstallerDecompressionStream -Algorithm Lzma -Stream $DataStream -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize -1 -LeaveOpen
    return [pscustomobject]@{
      InstallerStream = $InstallerStream
      DataStream      = $DataStream
      Decoder         = $Decoder
      Properties      = $Properties
      CompressedSize  = $CompressedSize
    }
  } catch {
    if ($Decoder) { $Decoder.Dispose() }
    if ($DataStream) { $DataStream.Dispose() }
    $InstallerStream.Dispose()
    throw
  }
}

function Close-InstallMateDecoderContext {
  <#
  .SYNOPSIS
    Dispose all streams owned by an InstallMate decoder context
  .PARAMETER Context
    Parsed context or metadata object produced by the corresponding format reader.
  #>
  param ([Parameter(Mandatory)][psobject]$Context)

  if ($Context.Decoder) { $Context.Decoder.Dispose() }
  if ($Context.DataStream) { $Context.DataStream.Dispose() }
  if ($Context.InstallerStream) { $Context.InstallerStream.Dispose() }
}

function Read-InstallMateDatabaseSegment {
  <#
  .SYNOPSIS
    Read and validate the first tzf3 installer-database segment
  .PARAMETER Decoder
    Compression framing or bounded decoder selected from validated format metadata.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Decoder)

  # The first decoded tzf3 segment must be the bounded installer database;
  # later segments contain file bodies and are consumed only during expansion.
  $Header = Read-InstallMateSequentialRecord -Stream $Decoder -Count 64
  if ([Text.Encoding]::ASCII.GetString($Header, 0, 4) -cne 'tzf3') { throw 'The decoded InstallMate stream does not begin with a tzf3 record.' }
  $SegmentType = [BitConverter]::ToUInt16($Header, 8)
  $DatabaseLength = [BitConverter]::ToUInt64($Header, 16)
  if ($SegmentType -ne 2) { throw "The first InstallMate tzf3 record has unexpected type $SegmentType." }
  if ($DatabaseLength -lt 4 -or $DatabaseLength -gt $Script:InstallMateMaximumDatabaseBytes -or $DatabaseLength -gt [int]::MaxValue) {
    throw "The InstallMate database exceeds the $($Script:InstallMateMaximumDatabaseBytes)-byte limit or is invalid."
  }
  $Bytes = Read-InstallMateSequentialRecord -Stream $Decoder -Count ([int]$DatabaseLength)
  $DatabaseSignature = [Text.Encoding]::ASCII.GetString($Bytes, 0, 4)
  if ($DatabaseSignature -notmatch '^tin[A-Za-z0-9]$') { throw "The InstallMate database signature is invalid: $DatabaseSignature" }
  [pscustomobject]@{
    Header            = $Header
    SegmentType       = $SegmentType
    Length            = [long]$DatabaseLength
    DatabaseSignature = $DatabaseSignature
    Bytes             = $Bytes
  }
}

function Get-InstallMateFileRecord {
  <#
  .SYNOPSIS
    Read structured file records from an InstallMate setup database
  .PARAMETER Database
    Windows Installer database or related transform path queried read-only.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Marker = [Text.Encoding]::ASCII.GetBytes("file`0`0`0`0")
  $Records = [Collections.Generic.List[object]]::new()
  # Marker matches become records only after validating the complete fixed
  # fields, bounded name, file size, and path-free leaf-name invariant.
  foreach ($Offset in @(Find-BinaryPattern -Bytes $Database -Pattern $Marker -Maximum $Script:InstallMateMaximumFileRecords)) {
    if ($Offset + 0x58 -gt $Database.Length) { continue }
    $FileSize = [BitConverter]::ToUInt64($Database, [int]$Offset + 0x3C)
    $NameLength = [BitConverter]::ToUInt32($Database, [int]$Offset + 0x54)
    if ($NameLength -eq 0 -or $NameLength -gt 32768 -or $Offset + 0x58 + $NameLength -gt $Database.Length) { continue }
    if ($FileSize -gt $Script:InstallMateMaximumSegmentBytes) { continue }
    $Name = [Text.Encoding]::UTF8.GetString($Database, [int]$Offset + 0x58, [int]$NameLength).TrimEnd([char]0)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0 -or $Name -match '[/\\]') { continue }
    $Key = [byte[]]::new(8)
    [Buffer]::BlockCopy($Database, [int]$Offset + 8, $Key, 0, $Key.Length)
    $ParentKey = [byte[]]::new(8)
    [Buffer]::BlockCopy($Database, [int]$Offset + 0x14, $ParentKey, 0, $ParentKey.Length)
    $Records.Add([pscustomobject]@{
        RecordOffset     = [long]$Offset
        Key              = [Convert]::ToHexString($Key)
        ParentKey        = [Convert]::ToHexString($ParentKey)
        SegmentType      = [BitConverter]::ToUInt16($Key, 0)
        FileName         = $Name
        UncompressedSize = [long]$FileSize
      })
  }
  $Records.ToArray()
}

function Read-InstallMateDatabaseInfo {
  <#
  .SYNOPSIS
    Decode InstallMate scope and file-table evidence from the first tzf3 record
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER ArchiveInfo
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][psobject]$ArchiveInfo
  )

  $Context = Open-InstallMateDecoderContext -Path $Path -ArchiveInfo $ArchiveInfo
  try { $Database = Read-InstallMateDatabaseSegment -Decoder $Context.Decoder }
  finally { Close-InstallMateDecoderContext -Context $Context }

  $InstallLevel = $null
  $InstallRecordOffset = $null
  # The install-level byte is mapped only for database generations whose record
  # layout has been corroborated. Exactly one valid candidate is required.
  if ($ArchiveInfo.FormatMajor -ge 15) {
    $Marker = [Text.Encoding]::ASCII.GetBytes("inst`0`0`0`0")
    $Candidates = @(
      Find-BinaryPattern -Bytes $Database.Bytes -Pattern $Marker -Maximum 16 |
        Where-Object { $_ + 0x1B4 -lt $Database.Bytes.Length -and $Database.Bytes[$_ + 0x1B4] -le 5 }
    )
    if ($Candidates.Count -eq 1) {
      $InstallRecordOffset = [long]$Candidates[0]
      $InstallLevel = [byte]$Database.Bytes[$InstallRecordOffset + 0x1B4]
    }
  }
  $FileRecords = @(Get-InstallMateFileRecord -Database $Database.Bytes)
  [pscustomobject]@{
    DatabaseSignature   = $Database.DatabaseSignature
    DatabaseLength      = $Database.Length
    InstallRecordOffset = $InstallRecordOffset
    InstallLevel        = $InstallLevel
    FileRecords         = $FileRecords
  }
}

function Get-InstallMateArchiveInfo {
  <#
  .SYNOPSIS
    Locate and validate an embedded Tarma TIZ archive header
  .DESCRIPTION
    InstallMate 9 and later identify internal archives with tiz1 through tiz4.
    Only signatures after the PE image are considered, which avoids matching
    format-name strings compiled into the setup stub.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Layout = Get-PELayout -Path $File.FullName
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + $Script:InstallMateMinimumHeaderBytes -gt $Stream.Length) {
      throw 'The InstallMate PE has no package overlay'
    }
    # Authenticode data can follow the TIZ stream but is not package content;
    # use its file offset as the upper archive boundary when present.
    $CertificateDirectory = $Layout.DataDirectories['Certificate']
    $DataEnd = if ($CertificateDirectory -and $CertificateDirectory.Rva -gt $OverlayOffset -and $CertificateDirectory.Rva -le $Stream.Length) {
      [long]$CertificateDirectory.Rva
    } else { [long]$Stream.Length }
  } finally { $Stream.Dispose() }

  $MaximumScanBytes = [Math]::Min($Script:InstallMateMaximumHeaderScanBytes, $DataEnd - $OverlayOffset)
  if ($MaximumScanBytes -lt $Script:InstallMateMinimumHeaderBytes) { throw 'The InstallMate package data is truncated' }
  # Search only a bounded overlay prefix and authenticate every signature with
  # version, reserved-field, and declared-size invariants.
  foreach ($SignatureText in @('tiz4', 'tiz3', 'tiz2', 'tiz1')) {
    $Signature = [Text.Encoding]::ASCII.GetBytes($SignatureText)
    foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Signature -StartOffset $OverlayOffset -Length $MaximumScanBytes -Maximum 32)) {
      if ($Offset + $Script:InstallMateMinimumHeaderBytes -gt $DataEnd) { continue }
      $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try { $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Script:InstallMateMinimumHeaderBytes } finally { $Stream.Dispose() }
      $FormatMajor = [BitConverter]::ToUInt16($Header, 4)
      $FormatMinor = [BitConverter]::ToUInt16($Header, 6)
      $Reserved = [BitConverter]::ToUInt64($Header, 8)
      $DeclaredArchiveSize = [BitConverter]::ToUInt64($Header, 16)
      $AvailableArchiveBytes = [uint64]($DataEnd - $Offset)
      if ($FormatMajor -eq 0 -or $FormatMajor -gt 64 -or $FormatMinor -gt 64 -or $Reserved -ne 0) { continue }
      if ($DeclaredArchiveSize -lt $Script:InstallMateMinimumHeaderBytes -or $DeclaredArchiveSize -gt $AvailableArchiveBytes + 64) { continue }

      return [pscustomobject]@{
        Signature             = $SignatureText
        FormatMajor           = [uint16]$FormatMajor
        FormatMinor           = [uint16]$FormatMinor
        FormatVersion         = "$FormatMajor.$FormatMinor"
        ArchiveOffset         = [long]$Offset
        DataEndOffset         = [long]$DataEnd
        AvailableArchiveBytes = $AvailableArchiveBytes
        DeclaredArchiveSize   = $DeclaredArchiveSize
        CertificateOffset     = if ($DataEnd -lt $File.Length) { [long]$DataEnd } else { $null }
        IsComplete            = $DeclaredArchiveSize -le $AvailableArchiveBytes + 64
      }
    }
  }
  throw 'The PE overlay does not contain a supported InstallMate TIZ archive header'
}

function Get-InstallMateInfo {
  <#
  .SYNOPSIS
    Read static InstallMate identity and TIZ archive evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $ArchiveInfo = Get-InstallMateArchiveInfo -Path $File.FullName
    # Identity values are named PE resources produced by InstallMate. They are
    # kept separate from the compressed database evidence used for scope/files.
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $VersionStrings = Get-PEVersionStringTable -Path $File.FullName -ErrorAction SilentlyContinue
    $ProductCode = ([string]$VersionStrings.ProductCode).Trim()
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { $ProductCode = $null }
    $PackageCode = ([string]$VersionStrings.PackageCode).Trim()
    if ([string]::IsNullOrWhiteSpace($PackageCode)) { $PackageCode = $null }
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    $DisplayName = ([string]$VersionInfo.ProductName).Trim()
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = ([string]$VersionInfo.FileDescription).Trim() }
    $RegistryWrites = @()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $DatabaseInfo = $null
    # Metadata remains useful when a newer database layout cannot be decoded;
    # expose the limitation as a warning and retain conservative PE evidence.
    try { $DatabaseInfo = Read-InstallMateDatabaseInfo -Path $File.FullName -ArchiveInfo $ArchiveInfo }
    catch { $Warnings.Add("The InstallMate setup database could not be decoded: $($_.Exception.Message)") }
    $ScopeInfo = Get-InstallMateScopeInfo -RequestedExecutionLevel $ExecutionLevel -InstallLevel $DatabaseInfo.InstallLevel
    if ($DatabaseInfo -and $ArchiveInfo.FormatMajor -lt 15) {
      $Warnings.Add("InstallMate database $($ArchiveInfo.FormatVersion) was decoded, but its install-level record layout is not yet mapped; scope falls back to PE elevation evidence.")
    } elseif ($DatabaseInfo -and $null -eq $DatabaseInfo.InstallLevel) {
      $Warnings.Add('The InstallMate database did not contain one unambiguous supported install-level record; scope falls back to PE elevation evidence.')
    }
    if ($ScopeInfo.SupportsDualScope) { $Warnings.Add('This InstallMate package has elevation-dependent scope; confirm whether its command line can select scope before creating duplicate WinGet installer entries.') }
    $Warnings.Add('InstallMate custom registry records and folder hierarchy are not decoded yet; validate custom ARP fields and associations in a VM.')

    [pscustomobject]@{
      InstallerType              = 'InstallMate'
      ProductCode                = $ProductCode
      ProductCodeEvidence        = if ($ProductCode) { 'Named StringFileInfo.ProductCode value in the PE version resource' } else { $null }
      PackageCode                = $PackageCode
      PackageName                = $DisplayName
      DisplayName                = $DisplayName
      ProductName                = $DisplayName
      DisplayVersion             = ([string]$VersionInfo.ProductVersion).Trim()
      Publisher                  = ([string]$VersionInfo.CompanyName).Trim()
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = $ScopeInfo.Scope
      DefaultScope               = $ScopeInfo.DefaultScope
      SupportedScopes            = $ScopeInfo.SupportedScopes
      SupportsDualScope          = $ScopeInfo.SupportsDualScope
      ScopeConfidence            = $ScopeInfo.Confidence
      ScopeEvidence              = $ScopeInfo.Evidence
      InstallLevel               = $ScopeInfo.InstallLevel
      InstallLevelName           = $ScopeInfo.InstallLevelName
      RequestedExecutionLevel    = $ExecutionLevel
      RegistryWrites             = $RegistryWrites
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry = $null
      ArchiveInfo                = $ArchiveInfo
      DatabaseInfo               = if ($DatabaseInfo) {
        [pscustomobject]@{
          Signature           = $DatabaseInfo.DatabaseSignature
          Length              = $DatabaseInfo.DatabaseLength
          InstallRecordOffset = $DatabaseInfo.InstallRecordOffset
          FileRecordCount     = $DatabaseInfo.FileRecords.Count
        }
      } else { $null }
      FileEntries                = if ($DatabaseInfo) { $DatabaseInfo.FileRecords } else { @() }
      ExtractedFiles             = if ($DatabaseInfo) { @($DatabaseInfo.FileRecords | Select-Object -ExpandProperty FileName) } else { @() }
      CanExpand                  = $null -ne $DatabaseInfo
      Warnings                   = @($Warnings)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallMate'; ParserMajor = 3; Sources = @('PE StringFileInfo version resource', 'PE application manifest', 'bounded TIZ raw-LZMA stream', 'tzf3 installer database and file records', 'InstallMate documented install-level behavior') }
    }
  }
}

function Expand-InstallMateInstaller {
  <#
  .SYNOPSIS
    Expand bounded files from an InstallMate TIZ package without executing setup
  .DESCRIPTION
    InstallMate file records do not directly expose their resolved installation
    folders. Files are exported under Payload/<record-key>/<file-name> so
    duplicate names remain distinct and no inferred paths are presented as real.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallMate-$([guid]::NewGuid().ToString('N'))") }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $ArchiveInfo = Get-InstallMateArchiveInfo -Path $File.FullName
    $Context = Open-InstallMateDecoderContext -Path $File.FullName -ArchiveInfo $ArchiveInfo
    $Results = [Collections.Generic.List[object]]::new()
    try {
      # Decode the catalog once, then match sequential tzf3 payload segments by
      # their structured type and uncompressed size rather than physical names.
      $Database = Read-InstallMateDatabaseSegment -Decoder $Context.Decoder
      $Outstanding = [Collections.Generic.List[object]]::new()
      foreach ($Record in @(Get-InstallMateFileRecord -Database $Database.Bytes)) { $Outstanding.Add($Record) }
      $Selected = @($Outstanding | Where-Object { Test-ExtractionPattern -Path "Payload/$($_.Key)/$($_.FileName)" -Pattern $Name })
      $RemainingSelected = $Selected.Count
      $DecodedBytes = $Database.Length + 64L
      $SegmentCount = 1

      # Raw LZMA is sequential: unselected segments must still be drained to
      # preserve decoder history, but they are copied to Stream.Null.
      while ($RemainingSelected -gt 0) {
        if (++$SegmentCount -gt $Script:InstallMateMaximumFileRecords + 256) { throw 'The InstallMate package exceeds the segment-count limit.' }
        $Header = Read-InstallMateSequentialRecord -Stream $Context.Decoder -Count 64
        if ([Text.Encoding]::ASCII.GetString($Header, 0, 4) -cne 'tzf3') { throw 'The InstallMate payload contains an invalid tzf3 segment.' }
        $SegmentType = [BitConverter]::ToUInt16($Header, 8)
        $SegmentLength = [BitConverter]::ToUInt64($Header, 16)
        if ($SegmentLength -gt $Script:InstallMateMaximumSegmentBytes -or $SegmentLength -gt [long]::MaxValue) { throw 'The InstallMate payload segment exceeds the size limit.' }
        if ($DecodedBytes + 64L + [long]$SegmentLength -gt $MaximumExpandedBytes) { throw "The InstallMate decoded stream exceeds the $MaximumExpandedBytes-byte output limit." }

        # Consume each catalog record at most once so repeated type/size pairs
        # retain their original stream order instead of aliasing one output.
        $Record = $Outstanding | Where-Object { $_.SegmentType -eq $SegmentType -and $_.UncompressedSize -eq [long]$SegmentLength } | Select-Object -First 1
        $IsSelected = $null -ne $Record -and (Test-ExtractionPattern -Path "Payload/$($Record.Key)/$($Record.FileName)" -Pattern $Name)
        if ($IsSelected) {
          $RelativePath = "Payload/$($Record.Key)/$($Record.FileName)"
          $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
          $Parent = [IO.Path]::GetDirectoryName($OutputPath)
          if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          if (Test-Path -LiteralPath $OutputPath) { throw "The InstallMate payload contains a duplicate output path: $RelativePath" }
          $Output = [IO.File]::Open($OutputPath, 'CreateNew', 'Write', 'None')
          try { $null = Copy-BoundedStream -Source $Context.Decoder -Destination $Output -MaximumBytes ([long]$SegmentLength) -ExpectedBytes ([long]$SegmentLength) }
          finally { $Output.Dispose() }
          $Results.Add((Get-Item -LiteralPath $OutputPath -Force))
          $RemainingSelected--
        } else {
          $null = Copy-BoundedStream -Source $Context.Decoder -Destination ([IO.Stream]::Null) -MaximumBytes ([long]$SegmentLength) -ExpectedBytes ([long]$SegmentLength)
        }
        if ($Record) { $null = $Outstanding.Remove($Record) }
        $DecodedBytes += 64L + [long]$SegmentLength
      }
    } finally { Close-InstallMateDecoderContext -Context $Context }
    $Results.ToArray()
  }
}

function Test-InstallMate {
  <#
  .SYNOPSIS
    Test whether a file contains a supported InstallMate TIZ header
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-InstallMateArchiveInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromInstallMate {
  <#
  .SYNOPSIS
    Read protocols when explicit InstallMate registry evidence is available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallMate {
  <#
  .SYNOPSIS
    Read file extensions when explicit InstallMate registry evidence is available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallMate {
  <#
  .SYNOPSIS
    Read the InstallMate PE product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromInstallMate {
  <#
  .SYNOPSIS
    Read the InstallMate PE product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).DisplayName }
}

function Read-PublisherFromInstallMate {
  <#
  .SYNOPSIS
    Read the InstallMate PE publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromInstallMate {
  <#
  .SYNOPSIS
    Read a literal InstallMate uninstall key when available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).ProductCode }
}

function Read-ScopeFromInstallMate {
  <#
  .SYNOPSIS
    Read InstallMate scope from explicit static evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallMateInfo, Expand-InstallMateInstaller, Test-InstallMate, Read-ProtocolsFromInstallMate, Read-FileExtensionsFromInstallMate, Read-ProductVersionFromInstallMate, Read-ProductNameFromInstallMate, Read-PublisherFromInstallMate, Read-ProductCodeFromInstallMate, Read-ScopeFromInstallMate
