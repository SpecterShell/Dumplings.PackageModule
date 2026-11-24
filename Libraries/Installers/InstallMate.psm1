# SPDX-License-Identifier: Apache-2.0
# Static Tarma InstallMate parser. This implementation is grounded in the
# InstallMate builder data files, shipped help, and structurally distinct
# InstallMate 2, 3, 5, 8, 9, and 11 media. It never loads or executes setup.
# Binary structure consumed here (LE integers unless stated otherwise):
#
#   InstallMate 2.x PE overlay
#   +-- "tiz1" + uint32 version=1
#   `-- zlib stream -> repeated "tzff" records
#       +-- 40-byte record header (payload size@+0x08, name length@+0x26)
#       +-- ANSI record name
#       `-- payload (first record is Setup.ini)
#
#   InstallMate 3+ PE overlay or .tsuarch section
#   +-- "tiz2"/"tiz3"/"tiz4" + builder minor@+0x04 + major@+0x06
#   +-- declared archive size@+0x10
#   +-- tiz2: RFC 1950 Zlib stream@+0x38
#   +-- tiz3: LZMA properties[5]@+0x38 + raw LZMA@+0x3D
#   `-- tiz4: LZMA2 property[1]@+0x38 + raw LZMA2@+0x39
#       +-- 64-byte "tzf3" record header
#       +-- type 2 "tin?" setup database
#       `-- repeated payload records
#
# Some compressed-EXE launchers contain a stub TIZ followed by the package TIZ.
# The parser validates each candidate and selects the one whose first decoded
# tzf3 record is a type-2 tin database. Unknown fields remain observed only.
#
# Sources:
# - https://tarma.com/support/im9/setup/cmdline.htm
# - https://tarma.com/support/im9/using/dialogs/build-advanced.htm
# - https://tarma.com/support/im11/using/packaging.htm
# - InstallMate 11 shipped Help, Data/TsuSymbolRules.imdata, Symbols.imdata, and
#   StandardRegistry.imdata files.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallMateMaximumHeaderScanBytes = 67108864
$Script:InstallMateMinimumHeaderBytes = 61
$Script:InstallMateLegacyHeaderBytes = 40
$Script:InstallMateMaximumLegacyConfigurationBytes = 4194304
$Script:InstallMateMaximumDatabaseBytes = 134217728
$Script:InstallMateMaximumFileRecords = 65536
$Script:InstallMateMaximumSegmentBytes = 17179869184
$Script:InstallMateMaximumArchiveCandidates = 64
$Script:InstallMateMaximumRecordStringBytes = 1048576
$Script:InstallMateKnownSymbolNames = @{
  403 = 'ProductCode'; 404 = 'ProductName'; 405 = 'ProductVersion'; 410 = 'UninstallKey'; 423 = 'PackageCode'; 426 = 'PRIMARYFOLDER'; 449 = 'MainProductCode'; 523 = 'TsuInstallLevel'
}

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
    Open one bounded decoder over a validated InstallMate TIZ archive
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
    # Each route supplies its exact compression boundary. This avoids treating
    # TIZ4's one-byte LZMA2 property as the five-byte TIZ3 LZMA property block.
    $Properties = if ($ArchiveInfo.PropertiesLength -gt 0) {
      Read-BinaryBytes -Stream $InstallerStream -Offset $ArchiveInfo.PropertiesOffset -Count $ArchiveInfo.PropertiesLength
    } else { $null }
    $DataOffset = [long]$ArchiveInfo.DataOffset
    $CompressedSize = $ArchiveInfo.DataEndOffset - $DataOffset
    if ($CompressedSize -le 0) { throw 'The InstallMate compressed stream is empty or truncated.' }
    $DataStream = New-BoundedReadStream -Stream $InstallerStream -Offset $DataOffset -Length $CompressedSize -LeaveOpen
    $Decoder = New-InstallerDecompressionStream -Algorithm $ArchiveInfo.CompressionAlgorithm -Stream $DataStream -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize -1 -LeaveOpen
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

function Read-InstallMateLegacyRecordHeader {
  <#
  .SYNOPSIS
    Read one bounded InstallMate 2.x tzff record header and name.
  .PARAMETER Decoder
    Sequential zlib decoder positioned at the start of a tzff record.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Decoder)

  $Header = Read-InstallMateSequentialRecord -Stream $Decoder -Count $Script:InstallMateLegacyHeaderBytes
  if ([Text.Encoding]::ASCII.GetString($Header, 0, 4) -cne 'tzff') { throw 'The decoded InstallMate 2 stream does not contain a tzff record.' }
  $PayloadLength = [BitConverter]::ToUInt32($Header, 8)
  $NameLength = [BitConverter]::ToUInt16($Header, 0x26)
  if ($NameLength -eq 0 -or $NameLength -gt 32768) { throw 'The InstallMate 2 record name length is invalid.' }
  if ([uint64]$PayloadLength -gt $Script:InstallMateMaximumSegmentBytes) { throw 'The InstallMate 2 record exceeds the payload-size limit.' }
  $NameBytes = Read-InstallMateSequentialRecord -Stream $Decoder -Count $NameLength
  $Name = [Text.Encoding]::UTF8.GetString($NameBytes).TrimEnd([char]0)
  if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0) { throw 'The InstallMate 2 record name is invalid.' }
  [pscustomobject]@{ Header = $Header; Name = $Name; NameLength = $NameLength; PayloadLength = [long]$PayloadLength }
}

function ConvertFrom-InstallMateLegacyText {
  <#
  .SYNOPSIS
    Decode the ANSI Setup.ini payload used by InstallMate 2.x.
  .PARAMETER Bytes
    Bounded Setup.ini bytes from the first tzff record.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  try { return [Text.Encoding]::GetEncoding(1252).GetString($Bytes) }
  catch { return [Text.Encoding]::Latin1.GetString($Bytes) }
}

function ConvertTo-InstallMateLegacySymbolValue {
  <#
  .SYNOPSIS
    Remove InstallMate 2.99's numeric symbol identifier and platform mask.
  .PARAMETER Value
    Raw value from the Setup.ini Symbols section.
  #>
  [OutputType([string])]
  param ([AllowEmptyString()][string]$Value)

  $Parts = $Value -split '\|', 3
  return $Parts.Count -eq 3 ? $Parts[2] : $Value
}

function Resolve-InstallMateLegacyValue {
  <#
  .SYNOPSIS
    Resolve deterministic Setup.ini symbols without evaluating registry reads.
  .PARAMETER Value
    Legacy InstallMate expression.
  .PARAMETER Symbols
    Case-insensitive literal symbol dictionary.
  .PARAMETER Depth
    Current recursion depth; bounded to prevent symbol cycles.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][Collections.IDictionary]$Symbols,
    [ValidateRange(0, 16)][int]$Depth = 0
  )

  if ([string]::IsNullOrWhiteSpace($Value) -or $Depth -ge 16) { return $Value }
  $Resolved = $Value
  foreach ($Match in @([regex]::Matches($Resolved, '<([A-Za-z0-9_]+)>'))) {
    $Name = $Match.Groups[1].Value
    $Replacement = switch -Regex ($Name) {
      '^(?i:ProgramFiles|PROGRAMFILES)$' { '%ProgramFiles(x86)%'; break }
      '^(?i:CommonFiles)$' { '%CommonProgramFiles(x86)%'; break }
      '^(?i:User_AppData|AppData)$' { '%APPDATA%'; break }
      '^(?i:Common_AppData)$' { '%ProgramData%'; break }
      default {
        if ($Symbols.Contains($Name)) { Resolve-InstallMateLegacyValue -Value ([string]$Symbols[$Name]) -Symbols $Symbols -Depth ($Depth + 1) }
        else { $null }
      }
    }
    if ($null -ne $Replacement -and $Replacement -ne $Match.Value) { $Resolved = $Resolved.Replace($Match.Value, $Replacement) }
  }
  return $Resolved
}

function ConvertTo-InstallMateLegacyRelativePath {
  <#
  .SYNOPSIS
    Convert a legacy Files-group destination to a safe installed relative path.
  .PARAMETER InstallDirectory
    Files-group InstallDir expression.
  .PARAMETER FileName
    Payload leaf name.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$InstallDirectory,
    [Parameter(Mandatory)][string]$FileName
  )

  if ($InstallDirectory -match '^(?i)<AppFolder>(?:[\\/](.*))?$') {
    $Suffix = ([string]$Matches[1]).Trim([char[]]@([char]'\', [char]'/'))
    return [string]::IsNullOrWhiteSpace($Suffix) ? $FileName : (Join-Path $Suffix $FileName)
  }
  $Namespace = (($InstallDirectory -replace '[<>:%*?"|]', '_') -replace '[\\/]+', '\').Trim('\\', '.')
  if ([string]::IsNullOrWhiteSpace($Namespace)) { $Namespace = 'Unknown' }
  return Join-Path (Join-Path '_destinations' $Namespace) $FileName
}

function ConvertFrom-InstallMateLegacyConfiguration {
  <#
  .SYNOPSIS
    Parse Setup.ini while preserving repeated Files groups and their destinations.
  .PARAMETER Text
    Decoded Setup.ini text.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Text)

  $Root = [ordered]@{}
  $Install = [ordered]@{}
  $Symbols = [ordered]@{}
  $Files = [Collections.Generic.List[object]]::new()
  $Section = ''
  $FilesInstallDirectory = ''
  foreach ($Line in $Text -split '\r\n|\n|\r') {
    $Trimmed = $Line.Trim()
    if ($Trimmed.Length -eq 0 -or $Trimmed.StartsWith(';')) { continue }
    if ($Trimmed -match '^\[([^]]+)\]$') {
      $Section = $Matches[1]
      if ($Section -ieq 'Files') { $FilesInstallDirectory = '' }
      continue
    }
    $Separator = $Line.IndexOf('=')
    if ($Separator -lt 0) { continue }
    $Key = $Line.Substring(0, $Separator).Trim()
    $Value = $Line.Substring($Separator + 1)
    switch -Regex ($Section) {
      '^$' { if (-not $Root.Contains($Key)) { $Root[$Key] = $Value }; break }
      '^(?i:Install)$' { $Install[$Key] = $Value; break }
      '^(?i:Symbols)$' { $Symbols[$Key] = ConvertTo-InstallMateLegacySymbolValue -Value $Value; break }
      '^(?i:Files)$' {
        if ($Key -ieq 'InstallDir') { $FilesInstallDirectory = $Value; break }
        if ($Key -ine 'File' -or [string]::IsNullOrWhiteSpace($FilesInstallDirectory)) { break }
        $Descriptor = ($Value -split '=', 2)[0]
        $Fields = $Descriptor -split '\|'
        if ($Fields.Count -lt 2 -or [string]::IsNullOrWhiteSpace($Fields[0])) { break }
        $ArchivePath = $Fields[0].Replace('/', '\')
        $FileName = [IO.Path]::GetFileName($ArchivePath)
        $Size = 0L
        if (-not [long]::TryParse($Fields[1], [ref]$Size) -or $Size -lt 0 -or $Size -gt $Script:InstallMateMaximumSegmentBytes) { break }
        $Files.Add([pscustomobject]@{
            RecordOffset = $null; Key = $ArchivePath; ParentKey = $null; SegmentType = $null; FileName = $FileName; UncompressedSize = $Size
            ArchivePath = $ArchivePath; InstallDirectory = $FilesInstallDirectory; RelativePath = ConvertTo-InstallMateLegacyRelativePath -InstallDirectory $FilesInstallDirectory -FileName $FileName
          })
        break
      }
    }
  }

  # InstallMate 2.25 stores product values in [Install]; 2.99 moves them into
  # typed [Symbols] entries. Normalize both without discarding the raw tables.
  $DisplayName = if ($Symbols.Contains('AppTitle')) { [string]$Symbols['AppTitle'] } else { [string]$Install['Title'] }
  $DisplayVersion = if ($Symbols.Contains('AppVersion')) { [string]$Symbols['AppVersion'] } elseif ($Install.Contains('Version')) { [string]$Install['Version'] } else { [string]$Root['Version'] }
  $Publisher = if ($Symbols.Contains('Company')) { [string]$Symbols['Company'] } else { [string]$Install['CompanyName'] }
  $ProductCode = if ($Symbols.Contains('Uninstall')) { Resolve-InstallMateLegacyValue -Value ([string]$Symbols['Uninstall']) -Symbols $Symbols } else { [string]$Install['UninstallKey'] }
  $InstallLocationExpression = if ($Symbols.Contains('AppFolder')) { [string]$Symbols['AppFolder'] } else { [string]$Install['InstallDir'] }
  $DefaultInstallLocation = Resolve-InstallMateLegacyValue -Value $InstallLocationExpression -Symbols $Symbols
  $UninstallRegPath = $Symbols.Contains('UninstallRegPath') ? (Resolve-InstallMateLegacyValue -Value ([string]$Symbols['UninstallRegPath']) -Symbols $Symbols) : $null
  $Scope = if ($UninstallRegPath -match '^(?i:HKEY_LOCAL_MACHINE|<HKLM>)') { 'machine' } elseif ($UninstallRegPath -match '^(?i:HKEY_CURRENT_USER|<HKCU>)') { 'user' } elseif ([string]$Install['AdminRights'] -eq '1') { 'machine' } else { $null }
  [pscustomobject]@{
    Root = $Root; Install = $Install; Symbols = $Symbols; FileRecords = $Files.ToArray(); DisplayName = $DisplayName; DisplayVersion = $DisplayVersion
    Publisher = $Publisher; ProductCode = $ProductCode; PackageCode = $null; DefaultInstallLocation = $DefaultInstallLocation; UninstallRegPath = $UninstallRegPath; Scope = $Scope
  }
}

function Read-InstallMateLegacyDatabaseInfo {
  <#
  .SYNOPSIS
    Decode the first Setup.ini record from an InstallMate 2.x TIZ1 package.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER ArchiveInfo
    Validated TIZ1 archive layout.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][psobject]$ArchiveInfo)

  $Context = Open-InstallMateDecoderContext -Path $Path -ArchiveInfo $ArchiveInfo
  try {
    $Record = Read-InstallMateLegacyRecordHeader -Decoder $Context.Decoder
    if ($Record.Name -cne 'Setup.ini') { throw "The first InstallMate 2 record is '$($Record.Name)', not Setup.ini." }
    if ($Record.PayloadLength -gt $Script:InstallMateMaximumLegacyConfigurationBytes -or $Record.PayloadLength -gt [int]::MaxValue) { throw 'The InstallMate 2 Setup.ini record exceeds the configuration-size limit.' }
    $Bytes = Read-InstallMateSequentialRecord -Stream $Context.Decoder -Count ([int]$Record.PayloadLength)
  } finally { Close-InstallMateDecoderContext -Context $Context }
  $Configuration = ConvertFrom-InstallMateLegacyConfiguration -Text (ConvertFrom-InstallMateLegacyText -Bytes $Bytes)
  [pscustomobject]@{
    DatabaseSignature = 'Setup.ini'; DatabaseLength = $Record.PayloadLength; InstallRecordOffset = $null; InstallLevel = $null
    FileRecords = $Configuration.FileRecords; SymbolRecords = @(); Symbols = $Configuration.Symbols
    Metadata = [pscustomobject]@{
      ProductCode = $Configuration.ProductCode; ProductName = $Configuration.DisplayName; ProductVersion = $Configuration.DisplayVersion
      PackageCode = $Configuration.PackageCode; Publisher = $Configuration.Publisher; DefaultInstallLocation = $Configuration.DefaultInstallLocation; Scope = $Configuration.Scope
    }
    Configuration = $Configuration
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

function Read-InstallMateDatabaseUInt32 {
  <#
  .SYNOPSIS
    Read one bounded little-endian uint32 from an InstallMate database.
  .PARAMETER Database
    Caller-owned decompressed database bytes.
  .PARAMETER Offset
    Zero-based database-relative byte offset.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset
  )

  if ($Offset -gt $Database.Length - 4) { throw "The InstallMate database uint32 at 0x$($Offset.ToString('X')) is truncated." }
  return [BitConverter]::ToUInt32($Database, $Offset)
}

function Read-InstallMateDatabaseKey {
  <#
  .SYNOPSIS
    Read one bounded eight-byte InstallMate object key.
  .PARAMETER Database
    Caller-owned decompressed database bytes.
  .PARAMETER Offset
    Zero-based database-relative byte offset.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset
  )

  if ($Offset -gt $Database.Length - 8) { throw "The InstallMate object key at 0x$($Offset.ToString('X')) is truncated." }
  return [Convert]::ToHexString($Database, $Offset, 8)
}

function Read-InstallMateDatabaseString {
  <#
  .SYNOPSIS
    Read one uint32-length-prefixed UTF-8 string and advance a bounded cursor.
  .PARAMETER Database
    Caller-owned decompressed database bytes.
  .PARAMETER Cursor
    Reference to the database-relative cursor. The cursor advances past the length and string bytes.
  .PARAMETER MaximumBytes
    Maximum accepted encoded string length.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ref]$Cursor,
    [ValidateRange(0, 16777216)][int]$MaximumBytes = $Script:InstallMateMaximumRecordStringBytes
  )

  $Offset = [int]$Cursor.Value
  $Length = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Offset
  if ($Length -gt $MaximumBytes -or [uint64]$Offset + 4 + $Length -gt [uint64]$Database.Length) {
    throw "The InstallMate string at 0x$($Offset.ToString('X')) is truncated or exceeds the $MaximumBytes-byte limit."
  }
  $Cursor.Value = $Offset + 4 + [int]$Length
  if ($Length -eq 0) { return '' }
  $Value = [Text.Encoding]::UTF8.GetString($Database, $Offset + 4, [int]$Length)
  if ($Value.IndexOf([char]0) -ge 0) { throw "The InstallMate string at 0x$($Offset.ToString('X')) contains an embedded null." }
  return $Value
}

function Get-InstallMateRecordOffset {
  <#
  .SYNOPSIS
    Locate bounded records with one exact eight-byte InstallMate tag.
  .PARAMETER Database
    Caller-owned decompressed database bytes.
  .PARAMETER Tag
    Four-character ASCII object tag whose remaining four bytes must be zero.
  #>
  [OutputType([long[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ValidatePattern('^[\x20-\x7E]{4}$')][string]$Tag
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes("$Tag`0`0`0`0")
  return [long[]]@(Find-BinaryPattern -Bytes $Database -Pattern $Marker -Maximum $Script:InstallMateMaximumFileRecords)
}

function Read-InstallMateComponentReference {
  <#
  .SYNOPSIS
    Decode the common current-generation component-reference prefix.
  .PARAMETER Database
    Caller-owned decompressed database bytes.
  .PARAMETER RecordOffset
    Database-relative start of the tagged record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$RecordOffset
  )

  $Count = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($RecordOffset + 0x10)
  if ($Count -gt 4096 -or [uint64]$RecordOffset + 0x14 + 8 * [uint64]$Count -gt [uint64]$Database.Length) {
    throw "The InstallMate component-reference table at 0x$($RecordOffset.ToString('X')) is invalid."
  }
  $Keys = [Collections.Generic.List[string]]::new([int]$Count)
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Keys.Add((Read-InstallMateDatabaseKey -Database $Database -Offset ($RecordOffset + 0x14 + 8 * $Index)))
  }
  [pscustomobject]@{ Count = [int]$Count; Keys = $Keys.ToArray(); EndOffset = $RecordOffset + 0x14 + 8 * [int]$Count }
}

function Get-InstallMateComponentRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate component names, conditions, and folder aliases.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'cmp9')) {
    $Offset = [int]$Offset64
    try {
      $Cursor = $Offset + 0x10
      $Name = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $FolderAlias = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $Condition = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      # Current cmp9 records retain one reserved uint32 between the condition
      # expression and the localized display-name field.
      $null = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      $DisplayName = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $DisplayTranslations = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      $Description = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $DescriptionTranslations = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      if ([string]::IsNullOrWhiteSpace($Name)) { continue }
      $Records.Add([pscustomobject]@{
          RecordOffset = [long]$Offset
          Key          = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          Name         = $Name
          FolderAlias  = $FolderAlias.Trim([char[]]@('<', '>'))
          Condition    = $Condition
          DisplayName  = $DisplayName
          DisplayTranslationCount = [uint32]$DisplayTranslations
          Description  = $Description
          DescriptionTranslationCount = [uint32]$DescriptionTranslations
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Copy-InstallMateRecord {
  <#
  .SYNOPSIS
    Copy one decoded record while replacing or appending derived properties.
  .PARAMETER Record
    Source parser record. The input object is not modified.
  .PARAMETER Property
    Ordered or unordered dictionary of derived property values.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Record,
    [Parameter(Mandatory)][Collections.IDictionary]$Property
  )

  $Properties = [ordered]@{}
  foreach ($SourceProperty in $Record.PSObject.Properties) { $Properties[$SourceProperty.Name] = $SourceProperty.Value }
  foreach ($Name in $Property.Keys) { $Properties[[string]$Name] = $Property[$Name] }
  return [pscustomobject]$Properties
}

function Add-InstallMateComponentEvidence {
  <#
  .SYNOPSIS
    Join component-owned records to their conditions without evaluating runtime state.
  .PARAMETER Record
    Records containing a Components property with zero or more component object keys.
  .PARAMETER ComponentRecord
    Decoded cmp9 records used to resolve component names and conditions.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$ComponentRecord
  )

  $Components = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Component in $ComponentRecord) { $Components[[string]$Component.Key] = $Component }

  foreach ($Item in $Record) {
    $Conditions = [Collections.Generic.List[object]]::new()
    $UnresolvedKeys = [Collections.Generic.List[string]]::new()
    foreach ($Key in @($Item.Components)) {
      if (-not $Components.ContainsKey([string]$Key)) {
        $UnresolvedKeys.Add([string]$Key)
        continue
      }
      $Component = $Components[[string]$Key]
      $Conditions.Add([pscustomobject]@{
          Key       = $Component.Key
          Name      = $Component.Name
          Condition = $Component.Condition
        })
    }
    $IsConditional = @($Conditions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Condition) }).Count -gt 0
    Copy-InstallMateRecord -Record $Item -Property ([ordered]@{
        ComponentConditions     = $Conditions.ToArray()
        UnresolvedComponentKeys = $UnresolvedKeys.ToArray()
        IsConditional           = $IsConditional
      })
  }
}

function Get-InstallMateFolderRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate folder ancestry and installed path segments.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'fldr')) {
    $Offset = [int]$Offset64
    try {
      $References = Read-InstallMateComponentReference -Database $Database -RecordOffset $Offset
      $ParentOffset = $Offset + 0x24 + 8 * $References.Count
      $Cursor = $ParentOffset + 8
      $Name = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $TranslationCount = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      if ($TranslationCount -ne 0) { continue }
      $Cursor += 4
      $PathSegment = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      if ([string]::IsNullOrWhiteSpace($Name)) { continue }
      $Records.Add([pscustomobject]@{
          RecordOffset = [long]$Offset
          Key          = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          ParentKey    = Read-InstallMateDatabaseKey -Database $Database -Offset $ParentOffset
          Components   = $References.Keys
          Name         = $Name
          PathSegment  = $PathSegment
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMateFileRecord {
  <#
  .SYNOPSIS
    Read structured file records from an InstallMate setup database
  .PARAMETER Database
    Windows Installer database or related transform path queried read-only.
  .PARAMETER DatabaseSignature
    Validated tin database generation selecting the record field layout.
  .PARAMETER FormatMajor
    First TIZ version word, used to distinguish verified tin5 record revisions.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ValidatePattern('^tin[A-Za-z0-9]$')][string]$DatabaseSignature,
    [uint16]$FormatMajor
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes("file`0`0`0`0")
  $Records = [Collections.Generic.List[object]]::new()
  # tin5 moved the fixed UTF-8 name fields relative to tin3. Current databases
  # instead carry a variable component-reference table, so every later field is
  # addressed from that table's validated count.
  if (-not (Test-InstallMateFileLayoutSupported -DatabaseSignature $DatabaseSignature -FormatMajor $FormatMajor)) { return @() }
  # Marker matches become records only after validating the complete fixed
  # fields, bounded name, file size, and path-free leaf-name invariant.
  foreach ($Offset in @(Find-BinaryPattern -Bytes $Database -Pattern $Marker -Maximum $Script:InstallMateMaximumFileRecords)) {
    try {
      if ($DatabaseSignature -in 'tin9', 'tinA', 'tinB') {
        $References = Read-InstallMateComponentReference -Database $Database -RecordOffset ([int]$Offset)
        $FolderOffset = [int]$Offset + 0x24 + 8 * $References.Count
        $FileSizeOffset = [int]$Offset + 0x34 + 8 * $References.Count
        $NameLengthOffset = [int]$Offset + 0x4C + 8 * $References.Count
        $ParentKey = Read-InstallMateDatabaseKey -Database $Database -Offset $FolderOffset
        $Components = $References.Keys
      } else {
        $FileSizeOffset = [int]$Offset + ($DatabaseSignature -ceq 'tin5' ? 0x38 : 0x3C)
        $NameLengthOffset = [int]$Offset + $(if ($DatabaseSignature -ceq 'tin5' -and $FormatMajor -le 2) { 0x4C } elseif ($DatabaseSignature -ceq 'tin5') { 0x50 } else { 0x54 })
        $ParentKey = Read-InstallMateDatabaseKey -Database $Database -Offset ([int]$Offset + 0x14)
        $Components = @()
      }
      $NameOffset = $NameLengthOffset + 4
      if ($FileSizeOffset -gt $Database.Length - 8 -or $NameLengthOffset -gt $Database.Length - 4) { continue }
      $FileSize = [BitConverter]::ToUInt64($Database, $FileSizeOffset)
      $NameLength = [BitConverter]::ToUInt32($Database, $NameLengthOffset)
      if ($NameLength -eq 0 -or $NameLength -gt 32768 -or [uint64]$NameOffset + $NameLength -gt [uint64]$Database.Length) { continue }
      if ($FileSize -gt $Script:InstallMateMaximumSegmentBytes) { continue }
      $Name = [Text.Encoding]::UTF8.GetString($Database, $NameOffset, [int]$NameLength).TrimEnd([char]0)
      if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0 -or $Name -match '[/\\]') { continue }
      $Key = Read-InstallMateDatabaseKey -Database $Database -Offset ([int]$Offset + 8)
      $Records.Add([pscustomobject]@{
          RecordOffset     = [long]$Offset
          Key              = $Key
          ParentKey        = $ParentKey
          Components       = $Components
          SegmentType      = [BitConverter]::ToUInt16($Database, [int]$Offset + 8)
          FileName         = $Name
          UncompressedSize = [long]$FileSize
          RelativePath     = $null
        })
    } catch { continue }
  }
  $Records.ToArray()
}

function Read-InstallMateLocalizedString {
  <#
  .SYNOPSIS
    Read a current InstallMate localized string whose default text is followed by translations.
  .PARAMETER Database
    Caller-owned decompressed database bytes.
  .PARAMETER Cursor
    Reference to the database-relative cursor, advanced past the complete localized value.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ref]$Cursor
  )

  $Default = Read-InstallMateDatabaseString -Database $Database -Cursor $Cursor
  $Count = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ([int]$Cursor.Value)
  $Cursor.Value = [int]$Cursor.Value + 4
  if ($Count -gt 4096) { throw 'The InstallMate localized-string translation count is invalid.' }
  $Translations = [Collections.Generic.List[object]]::new([int]$Count)
  for ($Index = 0; $Index -lt $Count; $Index++) {
    # InstallMate stores a uint32 language identifier followed by an LP UTF-8
    # translation. Controlled multilingual projects establish this framing.
    $Language = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ([int]$Cursor.Value)
    $Cursor.Value = [int]$Cursor.Value + 4
    $Value = Read-InstallMateDatabaseString -Database $Database -Cursor $Cursor
    $Translations.Add([pscustomobject]@{ Language = $Language; Value = $Value })
  }
  return [pscustomobject]@{ Default = $Default; Translations = $Translations.ToArray() }
}

function Get-InstallMateRegistryKeyRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate registry-key catalog records.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'regk')) {
    $Offset = [int]$Offset64
    try {
      $Cursor = $Offset + 0x24
      $Name = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $ViewCode = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $MirroredViewCode = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
      if ([string]::IsNullOrWhiteSpace($Name.Default)) { continue }
      # Controlled one-option builds map project RegView values 0..4 to runtime
      # codes 0, 2, 3, 4, and 5. Both stored words must agree before the policy
      # is trusted; codes 4 and 5 alone prove one fixed registry view.
      $ViewPolicies = @{
        0 = 'ExistingKeyElseNative'
        2 = 'NativeOnly'
        3 = '64BitThen32Bit'
        4 = '64BitOnly'
        5 = '32BitOnly'
      }
      $ViewPolicy = $ViewCode -eq $MirroredViewCode ? $ViewPolicies[[int]$ViewCode] : $null
      $Records.Add([pscustomobject]@{
          RecordOffset             = [long]$Offset
          Key                      = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          Name                     = $Name.Default
          NameTranslations         = $Name.Translations
          RegistryViewCode         = $ViewCode
          MirroredRegistryViewCode = $MirroredViewCode
          RegistryViewPolicy       = $ViewPolicy
          RegistryView             = if ($ViewPolicy -ceq '64BitOnly') { '64-bit' } elseif ($ViewPolicy -ceq '32BitOnly') { '32-bit' } else { $null }
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMateRegistryValueRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate registry-value operations and their parent key references.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'regv')) {
    $Offset = [int]$Offset64
    try {
      $References = Read-InstallMateComponentReference -Database $Database -RecordOffset $Offset
      $Cursor = $Offset + 0x2C + 8 * $References.Count
      $Name = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $Data = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $null = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      $ParentKey = Read-InstallMateDatabaseKey -Database $Database -Offset $Cursor
      $Cursor += 8
      $Type = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      $Flags = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Records.Add([pscustomobject]@{
          RecordOffset     = [long]$Offset
          Key              = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          ParentKey        = $ParentKey
          Components       = $References.Keys
          Name             = $Name.Default
          NameTranslations = $Name.Translations
          Data             = $Data.Default
          DataTranslations = $Data.Translations
          TypeCode         = $Type
          Flags            = $Flags
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMateEnvironmentRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate environment-variable operations.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  $InstallActions = @{
    0 = 'DoNotInstall'
    1 = 'InstallIfNotPresent'
    2 = 'InstallIfPresent'
    3 = 'Prepend'
    4 = 'Append'
    5 = 'Overwrite'
    6 = 'RemovePartialValue'
    7 = 'RemoveIfMatched'
    8 = 'RemoveCompletely'
  }
  $RemoveActions = @{
    0 = 'DoNotRemove'
    1 = 'RemovePartialValue'
    2 = 'RemoveIfMatched'
    3 = 'RemoveCompletely'
    4 = 'RestoreOriginal'
  }
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'evar')) {
    $Offset = [int]$Offset64
    try {
      $References = Read-InstallMateComponentReference -Database $Database -RecordOffset $Offset
      $InstallActionCode = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $References.EndOffset
      $RemoveActionWord = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($References.EndOffset + 4)
      $OptionWords = [uint32[]]@(
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($References.EndOffset + 8)
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($References.EndOffset + 12)
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($References.EndOffset + 16)
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($References.EndOffset + 20)
      )
      $Cursor = $Offset + 0x2C + 8 * $References.Count
      $Name = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $Data = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $SignedRemoveAction = [BitConverter]::ToInt32([BitConverter]::GetBytes($RemoveActionWord), 0)
      $RemoveActionCode = $SignedRemoveAction -in -4..0 ? - $SignedRemoveAction : $null
      $Separator = if ($OptionWords[3] -eq 0) { '' } elseif ($OptionWords[3] -le 0x10FFFF -and $OptionWords[3] -notin 0xD800..0xDFFF) { [char]::ConvertFromUtf32([int]$OptionWords[3]) } else { $null }
      $ConfigurationComplete = $null -ne $RemoveActionCode -and $InstallActions.ContainsKey([int]$InstallActionCode) -and $OptionWords[0] -eq 0 -and $OptionWords[1] -in 0, 1 -and $OptionWords[2] -in 0, 2 -and $null -ne $Separator
      $Records.Add([pscustomobject]@{
          RecordOffset             = [long]$Offset
          Key                      = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          Components               = $References.Keys
          Name                     = $Name.Default
          NameTranslations         = $Name.Translations
          Value                    = $Data.Default
          ValueTranslations        = $Data.Translations
          InstallActionCode        = $InstallActionCode
          InstallAction            = $InstallActions[[int]$InstallActionCode]
          RemoveActionCode         = $RemoveActionCode
          RemoveAction             = $null -ne $RemoveActionCode ? $RemoveActions[[int]$RemoveActionCode] : $null
          KeepDuringUpdates        = $OptionWords[1] -ne 0
          CurrentUserOnly          = $OptionWords[2] -ne 0
          ScopeBehavior            = $OptionWords[2] -ne 0 ? 'CurrentUser' : 'AllUsersWhenAvailable'
          Separator                = $Separator
          ConfigurationComplete    = $ConfigurationComplete
          ObservedRemoveActionWord = $RemoveActionWord
          ObservedOptionWords      = $OptionWords
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMateShortcutRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate shell-link records.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'shct')) {
    $Offset = [int]$Offset64
    try {
      $References = Read-InstallMateComponentReference -Database $Database -RecordOffset $Offset
      $FolderOffset = $Offset + 0x24 + 8 * $References.Count
      $Cursor = $FolderOffset + 16
      $Title = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $LinkName = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $Arguments = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $TargetPath = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $WorkingDirectory = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $IconPath = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $Records.Add([pscustomobject]@{
          RecordOffset     = [long]$Offset
          Key              = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          FolderKey        = Read-InstallMateDatabaseKey -Database $Database -Offset $FolderOffset
          Components       = $References.Keys
          Name             = $LinkName.Default
          Title            = $Title.Default
          Arguments        = $Arguments.Default
          TargetPath       = $TargetPath
          WorkingDirectory = $WorkingDirectory
          IconPath         = $IconPath
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMateExecutionRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate run-program action records.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'a206')) {
    $Offset = [int]$Offset64
    try {
      $Cursor = $Offset + 0x24
      $Name = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $Condition = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $Text = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $Cursor += 8
      $Timeout = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 12
      $TargetPath = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $WorkingDirectory = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $Arguments = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $ShellVerb = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      if ([string]::IsNullOrWhiteSpace($Name) -or $Timeout -gt 86400000) { continue }
      $Records.Add([pscustomobject]@{
          RecordOffset        = [long]$Offset
          Key                 = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          Name                = $Name
          Condition           = $Condition
          Text                = $Text.Default
          TimeoutMilliseconds = $Timeout
          TargetPath          = $TargetPath
          WorkingDirectory    = $WorkingDirectory
          Arguments           = $Arguments
          ShellVerb           = $ShellVerb
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMatePrerequisiteRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate prerequisite groups and their linked actions.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'preh')) {
    $Offset = [int]$Offset64
    try {
      # A preh record owns an internal name followed by the object keys of the
      # action records that implement its detection and installation behavior.
      $Cursor = $Offset + 0x10
      $Name = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $ActionCount = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      if ($ActionCount -gt 4096 -or [uint64]$Cursor + 8 * [uint64]$ActionCount -gt [uint64]$Database.Length) {
        throw "The InstallMate prerequisite action table at 0x$($Offset.ToString('X')) is invalid."
      }
      $ActionKeys = [Collections.Generic.List[string]]::new([int]$ActionCount)
      for ($Index = 0; $Index -lt $ActionCount; $Index++) {
        $ActionKeys.Add((Read-InstallMateDatabaseKey -Database $Database -Offset $Cursor))
        $Cursor += 8
      }

      # Controlled InstallMate 11 projects establish two option words, then the
      # platform mask triplet and a length-prefixed condition. A one-setting
      # build proves the second word is the documented Administrator-rights
      # requirement. The first word remains observed because its meaning has
      # not changed independently in the available fixtures.
      $ObservedOption1 = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $ObservedOption2 = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
      $CpuSupport = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 8)
      $ExeSupport = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 12)
      $ExeMatch = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 16)
      $Cursor += 20
      $Condition = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      if ([string]::IsNullOrWhiteSpace($Name)) { continue }
      $Records.Add([pscustomobject]@{
          RecordOffset          = [long]$Offset
          Key                   = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          Name                  = $Name
          ActionKeys            = $ActionKeys.ToArray()
          Actions               = @()
          Condition             = $Condition
          CpuSupport            = $CpuSupport
          ExeSupport            = $ExeSupport
          ExeMatch              = $ExeMatch
          RequiresAdministrator = $ObservedOption2 -ne 0
          ObservedOptions       = [uint32[]]@($ObservedOption1, $ObservedOption2)
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMateServiceRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate service configuration records.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  $ServiceTypeNames = @{
    1   = 'KernelDriver'
    2   = 'FileSystemDriver'
    16  = 'OwnProcess'
    32  = 'SharedProcess'
    272 = 'OwnInteractiveProcess'
    288 = 'SharedInteractiveProcess'
  }
  $StartTypeNames = @{ 0 = 'Boot'; 1 = 'System'; 2 = 'Automatic'; 3 = 'Manual'; 4 = 'Disabled' }
  $ErrorControlNames = @{ 0 = 'Ignore'; 1 = 'Normal'; 2 = 'Severe'; 3 = 'Critical' }
  $RecoveryActionNames = @{ 0 = 'TakeNoAction'; 1 = 'RestartService'; 2 = 'RestartComputer'; 3 = 'RunProgram' }
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'svc ')) {
    $Offset = [int]$Offset64
    try {
      $References = Read-InstallMateComponentReference -Database $Database -RecordOffset $Offset
      $Cursor = $Offset + 0x24 + 8 * $References.Count
      $Name = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)

      # Current records store four variable strings before the selected file
      # object. Reading through a cursor is required because arguments and
      # recovery-command text change the position of every following field.
      $Arguments = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $ObservedString1 = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $ObservedString2 = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $TargetFileKey = Read-InstallMateDatabaseKey -Database $Database -Offset $Cursor
      $Cursor += 8
      $TargetOption = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      $LoadOrderGroup = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $DependencyText = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $StartName = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $Password = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $ServiceType = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $StartTypeValue = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
      $ErrorControl = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 8)
      $Cursor += 12
      $DisplayName = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $Description = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)
      $RebootMessage = Read-InstallMateLocalizedString -Database $Database -Cursor ([ref]$Cursor)

      # The recovery command is always present as a length-prefixed UTF-8
      # string, including as a zero-length field. Recovery entries then use
      # fixed uint32 action/delay pairs; controlled projects establish that
      # the delay is compiled from seconds to milliseconds.
      $RunCommand = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $ResetPeriod = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $RecoveryActionCount = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
      if ($RecoveryActionCount -gt 1024) { throw "The InstallMate service recovery-action count at 0x$($Offset.ToString('X')) exceeds the record limit." }
      $Cursor += 8
      $RecoveryActions = [Collections.Generic.List[object]]::new([int]$RecoveryActionCount)
      for ($RecoveryIndex = 0; $RecoveryIndex -lt $RecoveryActionCount; $RecoveryIndex++) {
        $ActionCode = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
        $DelayMilliseconds = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
        $Cursor += 8
        $RecoveryActions.Add([pscustomobject]@{
            Sequence          = $RecoveryIndex + 1
            ActionCode        = $ActionCode
            Action            = $RecoveryActionNames[[int]$ActionCode]
            DelayMilliseconds = $DelayMilliseconds
            DelaySeconds      = [decimal]$DelayMilliseconds / 1000
          })
      }
      if ([string]::IsNullOrWhiteSpace($Name)) { continue }
      $Dependencies = [string[]]@($DependencyText.Split([char]0x1F, [StringSplitOptions]::RemoveEmptyEntries))
      $DelayedAutomaticStart = ($StartTypeValue -band 0x10000) -ne 0
      $StartType = $StartTypeValue -band 0xFFFF
      $Account = switch -CaseSensitive ($StartName) {
        'NT AUTHORITY\LocalService' { 'LocalService'; break }
        'NT AUTHORITY\NetworkService' { 'NetworkService'; break }
        default { [string]::IsNullOrWhiteSpace($StartName) ? 'LocalSystemOrUnspecified' : 'Other' }
      }
      $Records.Add([pscustomobject]@{
          RecordOffset              = [long]$Offset
          Key                       = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          Components                = $References.Keys
          Name                      = $Name
          DisplayName               = $DisplayName.Default
          DisplayNameTranslations   = $DisplayName.Translations
          Description               = $Description.Default
          DescriptionTranslations   = $Description.Translations
          BinaryPath                = $null
          TargetFileKey             = $TargetFileKey
          TargetOption              = $TargetOption
          Arguments                 = $Arguments
          RunCommand                = $RunCommand
          RebootMessage             = $RebootMessage.Default
          RebootMessageTranslations = $RebootMessage.Translations
          LoadOrderGroup            = $LoadOrderGroup
          Dependencies              = $Dependencies
          StartName                 = $StartName
          Account                   = $Account
          HasPassword               = -not [string]::IsNullOrEmpty($Password)
          ServiceType               = $ServiceType
          ServiceTypeName           = $ServiceTypeNames[[int]$ServiceType]
          StartType                 = $StartType
          StartTypeName             = $StartTypeNames[[int]$StartType]
          DelayedAutomaticStart     = $DelayedAutomaticStart
          ErrorControl              = $ErrorControl
          ErrorControlName          = $ErrorControlNames[[int]$ErrorControl]
          ResetPeriodSeconds        = $ResetPeriod
          RecoveryActionCount       = $RecoveryActionCount
          RecoveryActions           = $RecoveryActions.ToArray()
          ObservedOptions           = [uint32[]]@()
          ObservedStrings           = [string[]]@($ObservedString1, $ObservedString2)
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Get-InstallMateServiceControlRecord {
  <#
  .SYNOPSIS
    Decode current InstallMate service-control action records.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $ActionNames = @{
    0  = 'NoAction'
    1  = 'StartService'
    2  = 'StopService'
    4  = 'ResumeService'
    8  = 'PauseService'
    32 = 'DeleteService'
  }
  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'svca')) {
    $Offset = [int]$Offset64
    try {
      $References = Read-InstallMateComponentReference -Database $Database -RecordOffset $Offset
      $Cursor = $References.EndOffset

      # Controlled one-action builds establish four fixed words before the
      # service name. They remain evidence until independent builder settings
      # demonstrate their semantics.
      $ObservedOptions = [uint32[]]@(
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 8)
        Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 12)
      )
      $Cursor += 16
      $Name = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $Arguments = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $InstallActionCode = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $RemoveActionCode = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
      if ([string]::IsNullOrWhiteSpace($Name)) { continue }

      $InstallAction = $ActionNames[[int]$InstallActionCode]
      $RemoveAction = $ActionNames[[int]$RemoveActionCode]
      $Records.Add([pscustomobject]@{
          RecordOffset          = [long]$Offset
          Key                   = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          Components            = $References.Keys
          Name                  = $Name
          Arguments             = $Arguments
          InstallActionCode     = $InstallActionCode
          InstallAction         = $InstallAction
          RemoveActionCode      = $RemoveActionCode
          RemoveAction          = $RemoveAction
          ConfigurationComplete = $null -ne $InstallAction -and $null -ne $RemoveAction
          ObservedOptions       = $ObservedOptions
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Resolve-InstallMateSystemEffectRecord {
  <#
  .SYNOPSIS
    Add deterministic path and object-link projections to decoded system effects.
  .PARAMETER ShortcutRecord
    Decoded shortcut records whose folder and target expressions should be projected.
  .PARAMETER ExecutionRecord
    Decoded run-program records whose path expressions should be projected.
  .PARAMETER PrerequisiteRecord
    Decoded prerequisite records whose action keys should be linked.
  .PARAMETER ServiceRecord
    Decoded service records whose selected file objects should be linked.
  .PARAMETER ServiceControlRecord
    Decoded service-control actions whose literal arguments should be resolved.
  .PARAMETER FileRecord
    Decoded installed files used to resolve service binary paths.
  .PARAMETER FolderRecord
    Resolved folder graph used for shortcut destinations.
  .PARAMETER SymbolValues
    Case-insensitive symbol dictionary used for deterministic path resolution.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$ShortcutRecord,
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$ExecutionRecord,
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$PrerequisiteRecord,
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$ServiceRecord,
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$ServiceControlRecord,
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$FileRecord,
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$FolderRecord,
    [Parameter(Mandatory)][Collections.IDictionary]$SymbolValues
  )

  $Folders = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Folder in $FolderRecord) { $Folders[[string]$Folder.Key] = $Folder }
  $ResolvedActionList = [Collections.Generic.List[object]]::new()
  foreach ($Record in $ExecutionRecord) {
    $ResolvedActionList.Add((Copy-InstallMateRecord -Record $Record -Property ([ordered]@{
            ResolvedTargetPath       = Resolve-InstallMateManifestValue -Value ([string]$Record.TargetPath) -SymbolValues $SymbolValues
            ResolvedWorkingDirectory = Resolve-InstallMateManifestValue -Value ([string]$Record.WorkingDirectory) -SymbolValues $SymbolValues
            IsConditional            = -not [string]::IsNullOrWhiteSpace([string]$Record.Condition)
          })))
  }
  $ResolvedActions = $ResolvedActionList.ToArray()
  $Actions = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Action in $ResolvedActions) { $Actions[[string]$Action.Key] = $Action }
  $ResolvedShortcutList = [Collections.Generic.List[object]]::new()
  foreach ($Record in $ShortcutRecord) {
    $Folder = $Folders[[string]$Record.FolderKey]
    $LinkPath = if ($Folder -and $Folder.ResolvedPath -and -not [string]::IsNullOrWhiteSpace([string]$Record.Name)) { "$($Folder.ResolvedPath.TrimEnd('\'))\$($Record.Name)" } else { $null }
    $ResolvedShortcutList.Add((Copy-InstallMateRecord -Record $Record -Property ([ordered]@{
            ResolvedLinkPath         = $LinkPath
            ResolvedTargetPath       = Resolve-InstallMateManifestValue -Value ([string]$Record.TargetPath) -SymbolValues $SymbolValues
            ResolvedWorkingDirectory = Resolve-InstallMateManifestValue -Value ([string]$Record.WorkingDirectory) -SymbolValues $SymbolValues
            ResolvedIconPath         = Resolve-InstallMateManifestValue -Value ([string]$Record.IconPath) -SymbolValues $SymbolValues
          })))
  }
  $ResolvedShortcuts = $ResolvedShortcutList.ToArray()
  $ResolvedPrerequisiteList = [Collections.Generic.List[object]]::new()
  foreach ($Record in $PrerequisiteRecord) {
    $Linked = [Collections.Generic.List[object]]::new()
    foreach ($Key in $Record.ActionKeys) { if ($Actions.ContainsKey([string]$Key)) { $Linked.Add($Actions[[string]$Key]) } }
    $ResolvedPrerequisiteList.Add((Copy-InstallMateRecord -Record $Record -Property ([ordered]@{
            Actions       = $Linked.ToArray()
            IsConditional = -not [string]::IsNullOrWhiteSpace([string]$Record.Condition)
          })))
  }
  $ResolvedPrerequisites = $ResolvedPrerequisiteList.ToArray()
  $Files = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($File in $FileRecord) { $Files[[string]$File.Key] = $File }
  $ResolvedServiceList = [Collections.Generic.List[object]]::new()
  foreach ($Record in $ServiceRecord) {
    $TargetFile = $Files[[string]$Record.TargetFileKey]
    $ResolvedServiceList.Add((Copy-InstallMateRecord -Record $Record -Property ([ordered]@{
            BinaryPath         = $TargetFile ? [string]$TargetFile.InstalledPath : $null
            TargetFile         = $TargetFile
            TargetFileResolved = $null -ne $TargetFile
          })))
  }
  $ResolvedServiceControlList = [Collections.Generic.List[object]]::new()
  foreach ($Record in $ServiceControlRecord) {
    $ResolvedServiceControlList.Add((Copy-InstallMateRecord -Record $Record -Property ([ordered]@{
            ResolvedArguments = Resolve-InstallMateManifestValue -Value ([string]$Record.Arguments) -SymbolValues $SymbolValues
          })))
  }
  return [pscustomobject]@{
    Shortcuts        = $ResolvedShortcuts
    ExecutionActions = $ResolvedActions
    Prerequisites    = $ResolvedPrerequisites
    Services         = $ResolvedServiceList.ToArray()
    ServiceActions   = $ResolvedServiceControlList.ToArray()
  }
}

function Get-InstallMateInstallRecord {
  <#
  .SYNOPSIS
    Decode the variable-length current InstallMate package/ARP record.
  .PARAMETER Database
    Caller-owned decompressed tin9, tinA, or tinB database bytes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Database)

  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Offset64 in @(Get-InstallMateRecordOffset -Database $Database -Tag 'inst')) {
    $Offset = [int]$Offset64
    try {
      $Cursor = $Offset + 0x34
      $ArpText = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $null = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      $ProductCode = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $SetupName = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      # Loader + Download media proves that the first four bytes of the old
      # opaque 12-byte block are a normal length-prefixed package URL. Local
      # package fixtures store an empty URL, which had hidden the variable size.
      $PackageDownloadUrl = Read-InstallMateDatabaseString -Database $Database -Cursor ([ref]$Cursor)
      $ObservedOptionWord1 = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $ObservedOptionWord2 = Read-InstallMateDatabaseUInt32 -Database $Database -Offset ($Cursor + 4)
      $Cursor += 8
      $RuntimeKey = Read-InstallMateDatabaseKey -Database $Database -Offset $Cursor
      $Cursor += 8
      $InstallLevel = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      $Cursor += 4
      $Flags = Read-InstallMateDatabaseUInt32 -Database $Database -Offset $Cursor
      if ($InstallLevel -gt 5 -or [string]::IsNullOrWhiteSpace($ProductCode)) { continue }
      $ArpValues = [ordered]@{}
      foreach ($Pair in @($ArpText -split [char]0x1F)) {
        if ($Pair -notmatch '^(?<Name>[^=]+)=(?<Value>.*)$') { continue }
        $ArpValues[$Matches.Name] = $Matches.Value
      }
      $Records.Add([pscustomobject]@{
          RecordOffset            = [long]$Offset
          Key                     = Read-InstallMateDatabaseKey -Database $Database -Offset ($Offset + 8)
          ProductCode             = $ProductCode
          SetupName               = $SetupName
          PackageDownloadUrl      = $PackageDownloadUrl
          ObservedOptionWords     = [uint32[]]@($ObservedOptionWord1, $ObservedOptionWord2)
          InstallLevel            = [byte]$InstallLevel
          Flags                   = $Flags
          RuntimeKey              = $RuntimeKey
          AppsAndFeaturesTemplate = $ArpValues
        })
    } catch { continue }
  }
  return $Records.ToArray()
}

function Test-InstallMateFileLayoutSupported {
  <#
  .SYNOPSIS
    Test whether a tin database has a source-backed file-record layout.
  .PARAMETER DatabaseSignature
    Validated tin database generation.
  .PARAMETER FormatMajor
    First physical TIZ version word, used to select verified tin5 revisions.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][ValidatePattern('^tin[A-Za-z0-9]$')][string]$DatabaseSignature,
    [uint16]$FormatMajor
  )

  return $DatabaseSignature -in 'tin3', 'tin9', 'tinA', 'tinB' -or ($DatabaseSignature -ceq 'tin5' -and $FormatMajor -notin 3..6)
}

function Get-InstallMateSymbolRecord {
  <#
  .SYNOPSIS
    Read source-backed product symbols from a modern tin database.
  .PARAMETER Database
    Bounded decompressed tin database bytes.
  .PARAMETER DatabaseSignature
    Validated database signature selecting the symbol framing.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Database,
    [Parameter(Mandatory)][ValidatePattern('^tin[A-Za-z0-9]$')][string]$DatabaseSignature
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes("symb`0`0`0`0")
  $Records = [Collections.Generic.List[object]]::new()
  if ($DatabaseSignature -notin 'tin3', 'tin5', 'tin9', 'tinA', 'tinB') { return @() }
  foreach ($Offset in @(Find-BinaryPattern -Bytes $Database -Pattern $Marker -Maximum $Script:InstallMateMaximumFileRecords)) {
    $IdOffset = $DatabaseSignature -ceq 'tin3' ? 0x18 : 0x10
    if ($Offset + $IdOffset + 12 -gt $Database.Length) { continue }
    $Id = [BitConverter]::ToUInt32($Database, [int]$Offset + $IdOffset)
    $Name = $Id -le [int]::MaxValue ? $Script:InstallMateKnownSymbolNames[[int]$Id] : $null
    $ValueLength = 0L
    $ValueOffset = 0L

    if ($DatabaseSignature -in 'tin9', 'tinA', 'tinB') {
      # Current databases store name then value, each prefixed by uint32 length.
      $NameLength = [BitConverter]::ToUInt32($Database, [int]$Offset + 0x18)
      if ($NameLength -gt 32768 -or $Offset + 0x1C + $NameLength + 4 -gt $Database.Length) { continue }
      if ($NameLength -gt 0) { $Name = [Text.Encoding]::UTF8.GetString($Database, [int]$Offset + 0x1C, [int]$NameLength).TrimEnd([char]0) }
      $ValueLengthOffset = [long]$Offset + 0x1C + $NameLength
      $ValueLength = [BitConverter]::ToUInt32($Database, [int]$ValueLengthOffset)
      $ValueOffset = $ValueLengthOffset + 4
    } elseif ($DatabaseSignature -ceq 'tin3') {
      # tin3 stores the value before the trailing symbolic name.
      $ValueLength = [BitConverter]::ToUInt32($Database, [int]$Offset + 0x20)
      $ValueOffset = [long]$Offset + 0x24
    } else {
      # Verified tin5 databases use the same value-first framing at +0x18.
      $ValueLength = [BitConverter]::ToUInt32($Database, [int]$Offset + 0x18)
      $ValueOffset = [long]$Offset + 0x1C
    }
    if ($ValueLength -gt 1048576 -or $ValueOffset + $ValueLength -gt $Database.Length) { continue }
    if ([string]::IsNullOrWhiteSpace($Name)) { continue }
    $Value = [Text.Encoding]::UTF8.GetString($Database, [int]$ValueOffset, [int]$ValueLength).TrimEnd([char]0)
    $Records.Add([pscustomobject]@{ RecordOffset = [long]$Offset; Id = [uint32]$Id; Name = $Name; Value = $Value })
  }
  $Records.ToArray()
}

function Resolve-InstallMateSymbolValue {
  <#
  .SYNOPSIS
    Resolve bounded literal angle-bracket references between tin symbols.
  .PARAMETER Value
    Symbol expression to resolve.
  .PARAMETER SymbolValues
    Case-insensitive symbol dictionary.
  .PARAMETER Depth
    Current bounded recursion depth.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][Collections.IDictionary]$SymbolValues,
    [ValidateRange(0, 16)][int]$Depth = 0
  )

  if ([string]::IsNullOrWhiteSpace($Value) -or $Depth -ge 16) { return $Value }
  $Resolved = $Value
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  for ($Iteration = $Depth; $Iteration -lt 16 -and $Seen.Add($Resolved); $Iteration++) {
    $Previous = $Resolved
    foreach ($Match in @([regex]::Matches($Previous, '<([A-Za-z0-9_]+)>'))) {
      $Name = $Match.Groups[1].Value
      if ($SymbolValues.Contains($Name)) { $Resolved = $Resolved.Replace($Match.Value, [string]$SymbolValues[$Name]) }
    }
    # Alias symbols such as PRIMARYFOLDER contain the bare name INSTALLDIR.
    if ($SymbolValues.Contains($Resolved)) { $Resolved = [string]$SymbolValues[$Resolved] }
    if ($Resolved -ceq $Previous) { break }
  }
  return $Resolved
}

function Resolve-InstallMateManifestValue {
  <#
  .SYNOPSIS
    Resolve deterministic InstallMate symbols and convert known folders to manifest-safe variables.
  .PARAMETER Value
    InstallMate expression containing angle-bracket symbols.
  .PARAMETER SymbolValues
    Case-insensitive symbol dictionary decoded from the setup database.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][Collections.IDictionary]$SymbolValues
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
  $KnownFolders = [ordered]@{
    ProgramFilesXFolder = '%ProgramFiles%'; ProgramFiles64Folder = '%ProgramFiles%'; ProgramFilesFolder = '%ProgramFiles(x86)%'
    CommonFilesXFolder = '%CommonProgramFiles%'; CommonFiles64Folder = '%CommonProgramFiles%'; CommonFilesFolder = '%CommonProgramFiles(x86)%'
    LocalAppDataFolder = '%LOCALAPPDATA%'; AppDataFolder = '%APPDATA%'; CommonAppDataFolder = '%ProgramData%'
    WindowsFolder = '%WINDIR%'; SystemFolder = '%WINDIR%\System32'; System64Folder = '%WINDIR%\System32'; SystemXFolder = '%WINDIR%\System32'
    ProfileFolder = '%USERPROFILE%'; PersonalFolder = '%USERPROFILE%\Documents'; DesktopFolder = '%USERPROFILE%\Desktop'
    CommonDesktopFolder = '%PUBLIC%\Desktop'; CommonDocumentsFolder = '%PUBLIC%\Documents'; TempFolder = '%TEMP%'
  }
  $Resolved = $Value
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  for ($Iteration = 0; $Iteration -lt 16 -and $Seen.Add($Resolved); $Iteration++) {
    $Previous = $Resolved
    foreach ($Match in @([regex]::Matches($Previous, '<([A-Za-z0-9_]+)>'))) {
      $Name = $Match.Groups[1].Value
      $Replacement = if ($KnownFolders.Contains($Name)) { [string]$KnownFolders[$Name] } elseif ($SymbolValues.Contains($Name)) { [string]$SymbolValues[$Name] } else { $null }
      if ($null -ne $Replacement) { $Resolved = $Resolved.Replace($Match.Value, $Replacement) }
    }
    if ($SymbolValues.Contains($Resolved)) { $Resolved = [string]$SymbolValues[$Resolved] }
    if ($Resolved -ceq $Previous) { break }
  }
  return $Resolved
}

function Resolve-InstallMateFolderGraph {
  <#
  .SYNOPSIS
    Resolve current InstallMate folder records into deterministic installed paths.
  .PARAMETER FolderRecord
    Decoded folder records linked by eight-byte object keys.
  .PARAMETER SymbolValues
    Case-insensitive symbol dictionary used to resolve path segments.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FolderRecord,
    [Parameter(Mandatory)][Collections.IDictionary]$SymbolValues
  )

  $ByKey = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Record in $FolderRecord) { $ByKey[[string]$Record.Key] = $Record }
  $Cache = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Resolving = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  function Resolve-FolderPath {
    param (
      [Parameter(Mandatory)][string]$Key,
      [Parameter(Mandatory)][Collections.IDictionary]$Symbols,
      [ValidateRange(0, 64)][int]$Depth = 0
    )
    if ($Cache.ContainsKey($Key)) { return $Cache[$Key] }
    if ($Depth -ge 64 -or -not $ByKey.ContainsKey($Key) -or -not $Resolving.Add($Key)) { return $null }
    try {
      $Record = $ByKey[$Key]
      $KnownRoot = Resolve-InstallMateManifestValue -Value "<$($Record.Name)>" -SymbolValues $Symbols
      if ($KnownRoot -and $KnownRoot -notmatch '<[^>]+>' -and $KnownRoot -match '^%[^%]+%') {
        $Path = $KnownRoot
      } else {
        $Parent = [string]$Record.ParentKey
        $ParentPath = $Parent -and $Parent -cne '0000000000000000' ? (Resolve-FolderPath -Key $Parent -Symbols $Symbols -Depth ($Depth + 1)) : $null
        $Segment = Resolve-InstallMateManifestValue -Value ([string]$Record.PathSegment) -SymbolValues $Symbols
        $Path = if ($ParentPath -and $Segment -and $Segment -notmatch '<[^>]+>') { "$($ParentPath.TrimEnd('\'))\$($Segment.TrimStart('\'))" } elseif ($KnownRoot -and $KnownRoot -notmatch '<[^>]+>') { $KnownRoot } else { $null }
      }
      if ($Path) { $Cache[$Key] = $Path }
      return $Path
    } finally { $null = $Resolving.Remove($Key) }
  }

  foreach ($Record in $FolderRecord) {
    $Path = Resolve-FolderPath -Key ([string]$Record.Key) -Symbols $SymbolValues
    Copy-InstallMateRecord -Record $Record -Property ([ordered]@{ ResolvedPath = $Path })
  }
}

function Resolve-InstallMateInstalledFilePath {
  <#
  .SYNOPSIS
    Project modern file records to safe paths relative to the primary installation folder.
  .PARAMETER FileRecord
    Decoded current file records.
  .PARAMETER FolderRecord
    Folder graph records carrying resolved paths.
  .PARAMETER PrimaryFolderName
    Resolved primary-folder alias, normally INSTALLDIR.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileRecord,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FolderRecord,
    [AllowNull()][string]$PrimaryFolderName
  )

  $Folders = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Folder in $FolderRecord) { $Folders[[string]$Folder.Key] = $Folder }
  $Primary = @($FolderRecord | Where-Object Name -EQ $PrimaryFolderName | Select-Object -First 1)
  foreach ($Record in $FileRecord) {
    $Folder = $Folders[[string]$Record.ParentKey]
    $RelativePath = $null
    if ($Folder -and $Primary.Count -eq 1 -and $Folder.ResolvedPath -and $Primary[0].ResolvedPath -and $Folder.ResolvedPath.StartsWith($Primary[0].ResolvedPath, [StringComparison]::OrdinalIgnoreCase)) {
      $Directory = $Folder.ResolvedPath.Substring($Primary[0].ResolvedPath.Length).Trim('\')
      $RelativePath = $Directory ? "$Directory\$($Record.FileName)" : $Record.FileName
    } elseif ($Folder) {
      $SafeFolder = ([string]$Folder.Name -replace '[^A-Za-z0-9._-]', '_').Trim('_')
      if (-not $SafeFolder) { $SafeFolder = $Record.ParentKey }
      $RelativePath = "_destinations\$SafeFolder\$($Record.FileName)"
    }
    Copy-InstallMateRecord -Record $Record -Property ([ordered]@{
        RelativePath  = $RelativePath
        InstalledPath = $Folder -and $Folder.ResolvedPath ? "$($Folder.ResolvedPath.TrimEnd('\'))\$($Record.FileName)" : $null
      })
  }
}

function ConvertTo-InstallMateRegistryWrite {
  <#
  .SYNOPSIS
    Project decoded current registry records into shared literal registry-write evidence.
  .PARAMETER RegistryValueRecord
    Decoded registry-value records.
  .PARAMETER RegistryKeyRecord
    Registry-key records used to resolve parent aliases.
  .PARAMETER SymbolValues
    Decoded setup symbols used to resolve key and value expressions.
  .PARAMETER Scope
    Proven single installation scope used to resolve HKEY_ALL_USERS.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryValueRecord,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryKeyRecord,
    [Parameter(Mandatory)][Collections.IDictionary]$SymbolValues,
    [AllowNull()][string]$Scope
  )

  $Keys = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Record in $RegistryKeyRecord) { $Keys[[string]$Record.Key] = $Record }
  $TypeNames = @{ 0 = 'None'; 1 = 'String'; 2 = 'ExpandString'; 3 = 'Binary'; 4 = 'DWord'; 5 = 'DWordBigEndian'; 6 = 'Link'; 7 = 'MultiString'; 11 = 'QWord' }
  foreach ($Record in $RegistryValueRecord) {
    if (-not $Keys.ContainsKey([string]$Record.ParentKey)) { continue }
    $KeyRecord = $Keys[[string]$Record.ParentKey]
    $Expression = Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues[[string]$KeyRecord.Name]) -SymbolValues $SymbolValues
    $Root = $null
    $Key = $null
    if ($Expression -match '^(?:<(?<ShortRoot>HKLM|HKCU|HKCR|HKAU)>|(?<LongRoot>HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_ALL_USERS))\\?(?<Key>.*)$') {
      $Root = if ($Matches.ShortRoot) { $Matches.ShortRoot } else { switch ($Matches.LongRoot) { HKEY_LOCAL_MACHINE { 'HKLM' } HKEY_CURRENT_USER { 'HKCU' } HKEY_CLASSES_ROOT { 'HKCR' } default { 'HKAU' } } }
      $Key = $Matches.Key
      if ($Root -ceq 'HKAU') { $Root = $Scope -ceq 'machine' ? 'HKLM' : ($Scope -ceq 'user' ? 'HKCU' : 'HKAU') }
    }
    $Name = Resolve-InstallMateSymbolValue -Value ([string]$Record.Name) -SymbolValues $SymbolValues
    $Value = Resolve-InstallMateManifestValue -Value ([string]$Record.Data) -SymbolValues $SymbolValues
    $Complete = $Root -in 'HKLM', 'HKCU', 'HKCR' -and $Key -notmatch '<[^>]+>' -and $Name -notmatch '<[^>]+>' -and $Value -notmatch '<[^>]+>'
    $UnresolvedComponentKeys = $Record.PSObject.Properties['UnresolvedComponentKeys'] ? @($Record.UnresolvedComponentKeys) : @()
    $ComponentConditions = $Record.PSObject.Properties['ComponentConditions'] ? @($Record.ComponentConditions) : @()
    $IsConditional = $Record.PSObject.Properties['IsConditional'] -and [bool]$Record.IsConditional
    $ComponentReferencesComplete = $UnresolvedComponentKeys.Count -eq 0
    $IsAuthoritative = $Complete -and $ComponentReferencesComplete -and -not $IsConditional
    [pscustomobject]@{
      Root = $Root; Key = $Key; Name = $Name; Value = $Value; Type = $TypeNames[[int]$Record.TypeCode]
      RegistryView = $KeyRecord.RegistryView; RegistryViewPolicy = $KeyRecord.RegistryViewPolicy
      Complete = $Complete; IsAuthoritative = $IsAuthoritative; IsConditional = $IsConditional
      Components = $Record.Components; ComponentConditions = $ComponentConditions
      UnresolvedComponentKeys = $UnresolvedComponentKeys; Source = $Record
    }
  }
}

function Get-InstallMateAppsAndFeaturesProjection {
  <#
  .SYNOPSIS
    Build visible Apps & Features entries from the built-in template and explicit uninstall writes.
  .PARAMETER InstallRecord
    Unique decoded current package record containing built-in ARP configuration.
  .PARAMETER RegistryWrite
    Literal custom registry writes projected from regv records.
  .PARAMETER SymbolValues
    Decoded setup symbols used to resolve built-in ARP values.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][psobject]$InstallRecord,
    [AllowNull()][object[]]$RegistryWrite,
    [Parameter(Mandatory)][Collections.IDictionary]$SymbolValues
  )

  $Entries = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
  $BuiltInValues = [ordered]@{}
  if ($InstallRecord -and $InstallRecord.AppsAndFeaturesTemplate.Count -gt 0) {
    foreach ($Pair in $InstallRecord.AppsAndFeaturesTemplate.GetEnumerator()) {
      $BuiltInValues[$Pair.Key] = Resolve-InstallMateManifestValue -Value ([string]$Pair.Value) -SymbolValues $SymbolValues
    }
    $DisplayName = [string]$BuiltInValues['DisplayName']
    if (-not [string]::IsNullOrWhiteSpace($InstallRecord.ProductCode) -and -not [string]::IsNullOrWhiteSpace($DisplayName) -and $DisplayName -notmatch '<[^>]+>') {
      $Entry = [ordered]@{ ProductCode = [string]$InstallRecord.ProductCode; InstallerType = 'exe'; DisplayName = $DisplayName }
      foreach ($Name in 'DisplayVersion', 'Publisher') {
        $Value = [string]$BuiltInValues[$Name]
        if (-not [string]::IsNullOrWhiteSpace($Value) -and $Value -notmatch '<[^>]+>') { $Entry[$Name] = $Value }
      }
      $Entries[[string]$InstallRecord.ProductCode] = [pscustomobject]$Entry
    }
  }

  # Explicit uninstall writes have runtime precedence over the generated row.
  # Group complete writes by physical key and omit SystemComponent rows.
  foreach ($Group in @($RegistryWrite | Where-Object { $_.IsAuthoritative -and $_.Root -in 'HKLM', 'HKCU' -and $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)[^\\]+$' } | Group-Object Root, RegistryView, Key)) {
    $Values = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Write in $Group.Group) { $Values[[string]$Write.Name] = $Write.Value }
    [long]$SystemComponent = 0
    $Hidden = $Values.ContainsKey('SystemComponent') -and [long]::TryParse([string]$Values['SystemComponent'], [ref]$SystemComponent) -and $SystemComponent -ne 0
    $DisplayName = $Values.ContainsKey('DisplayName') ? [string]$Values['DisplayName'] : $null
    if ($Hidden -or [string]::IsNullOrWhiteSpace($DisplayName)) { continue }
    $ProductCode = ([string]$Group.Group[0].Key -split '\\')[-1]
    $Entry = [ordered]@{ ProductCode = $ProductCode; InstallerType = 'exe'; DisplayName = $DisplayName }
    foreach ($Name in 'DisplayVersion', 'Publisher') {
      if ($Values.ContainsKey($Name) -and -not [string]::IsNullOrWhiteSpace([string]$Values[$Name])) { $Entry[$Name] = [string]$Values[$Name] }
    }
    $Entries[$ProductCode] = [pscustomobject]$Entry
  }

  return [pscustomobject]@{ Entries = @($Entries.Values); BuiltInValues = $BuiltInValues }
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

  $IsCurrentDatabase = $Database.DatabaseSignature -in 'tin9', 'tinA', 'tinB'
  # Current install records contain variable-length ARP and setup-name strings.
  # Decode through a cursor rather than relying on the old accidental +0x1B4
  # offset, which changed whenever the compiled setup name changed length.
  $InstallRecords = if ($IsCurrentDatabase) { @(Get-InstallMateInstallRecord -Database $Database.Bytes) } else { @() }
  $InstallRecord = $InstallRecords.Count -eq 1 ? $InstallRecords[0] : $null
  $InstallLevel = $InstallRecord ? [Nullable[byte]]$InstallRecord.InstallLevel : $null
  $InstallRecordOffset = $InstallRecord ? [long]$InstallRecord.RecordOffset : $null
  $FileLayoutSupported = Test-InstallMateFileLayoutSupported -DatabaseSignature $Database.DatabaseSignature -FormatMajor $ArchiveInfo.FormatMajor
  $RawFileRecords = if ($FileLayoutSupported) { @(Get-InstallMateFileRecord -Database $Database.Bytes -DatabaseSignature $Database.DatabaseSignature -FormatMajor $ArchiveInfo.FormatMajor) } else { @() }
  $SymbolRecords = @(Get-InstallMateSymbolRecord -Database $Database.Bytes -DatabaseSignature $Database.DatabaseSignature)
  $SymbolValues = [ordered]@{}
  foreach ($Record in $SymbolRecords) { if (-not [string]::IsNullOrWhiteSpace($Record.Name)) { $SymbolValues[$Record.Name] = $Record.Value } }
  $Components = if ($IsCurrentDatabase) { @(Get-InstallMateComponentRecord -Database $Database.Bytes) } else { @() }
  $RawFolders = if ($IsCurrentDatabase) { @(Get-InstallMateFolderRecord -Database $Database.Bytes) } else { @() }
  if ($IsCurrentDatabase) { $RawFolders = @(Add-InstallMateComponentEvidence -Record $RawFolders -ComponentRecord $Components) }
  $Folders = if ($IsCurrentDatabase) { @(Resolve-InstallMateFolderGraph -FolderRecord $RawFolders -SymbolValues $SymbolValues) } else { @() }
  $PrimaryFolderName = ([string]$SymbolValues['PRIMARYFOLDER']).Trim([char[]]@('<', '>'))
  if ([string]::IsNullOrWhiteSpace($PrimaryFolderName)) { $PrimaryFolderName = 'INSTALLDIR' }
  if ($IsCurrentDatabase) { $RawFileRecords = @(Add-InstallMateComponentEvidence -Record $RawFileRecords -ComponentRecord $Components) }
  $FileRecords = if ($IsCurrentDatabase -and $RawFileRecords.Count -gt 0) { @(Resolve-InstallMateInstalledFilePath -FileRecord $RawFileRecords -FolderRecord $Folders -PrimaryFolderName $PrimaryFolderName) } else { $RawFileRecords }
  $RegistryKeys = if ($IsCurrentDatabase) { @(Get-InstallMateRegistryKeyRecord -Database $Database.Bytes) } else { @() }
  $RegistryValueRecords = if ($IsCurrentDatabase) { @(Get-InstallMateRegistryValueRecord -Database $Database.Bytes) } else { @() }
  $EnvironmentRecords = if ($IsCurrentDatabase) { @(Get-InstallMateEnvironmentRecord -Database $Database.Bytes) } else { @() }
  [object[]]$RawShortcutRecords = if ($IsCurrentDatabase) { @(Get-InstallMateShortcutRecord -Database $Database.Bytes) } else { @() }
  [object[]]$RawExecutionRecords = if ($IsCurrentDatabase) { @(Get-InstallMateExecutionRecord -Database $Database.Bytes) } else { @() }
  [object[]]$RawPrerequisiteRecords = if ($IsCurrentDatabase) { @(Get-InstallMatePrerequisiteRecord -Database $Database.Bytes) } else { @() }
  [object[]]$RawServiceRecords = if ($IsCurrentDatabase) { @(Get-InstallMateServiceRecord -Database $Database.Bytes) } else { @() }
  [object[]]$RawServiceControlRecords = if ($IsCurrentDatabase) { @(Get-InstallMateServiceControlRecord -Database $Database.Bytes) } else { @() }
  if ($IsCurrentDatabase) {
    $RegistryValueRecords = @(Add-InstallMateComponentEvidence -Record $RegistryValueRecords -ComponentRecord $Components)
    $EnvironmentRecords = @(Add-InstallMateComponentEvidence -Record $EnvironmentRecords -ComponentRecord $Components)
    $RawShortcutRecords = [object[]]@(Add-InstallMateComponentEvidence -Record $RawShortcutRecords -ComponentRecord $Components)
    $RawServiceRecords = [object[]]@(Add-InstallMateComponentEvidence -Record $RawServiceRecords -ComponentRecord $Components)
    $RawServiceControlRecords = [object[]]@(Add-InstallMateComponentEvidence -Record $RawServiceControlRecords -ComponentRecord $Components)
  }
  if ($null -eq $RawShortcutRecords) { $RawShortcutRecords = [object[]]@() }
  if ($null -eq $RawExecutionRecords) { $RawExecutionRecords = [object[]]@() }
  if ($null -eq $RawPrerequisiteRecords) { $RawPrerequisiteRecords = [object[]]@() }
  if ($null -eq $RawServiceRecords) { $RawServiceRecords = [object[]]@() }
  if ($null -eq $RawServiceControlRecords) { $RawServiceControlRecords = [object[]]@() }
  $SystemEffects = Resolve-InstallMateSystemEffectRecord -ShortcutRecord $RawShortcutRecords -ExecutionRecord $RawExecutionRecords -PrerequisiteRecord $RawPrerequisiteRecords -ServiceRecord $RawServiceRecords -ServiceControlRecord $RawServiceControlRecords -FileRecord $FileRecords -FolderRecord $Folders -SymbolValues $SymbolValues
  $ProductCode = $InstallRecord ? [string]$InstallRecord.ProductCode : (Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues['UninstallKey']) -SymbolValues $SymbolValues)
  if ([string]::IsNullOrWhiteSpace($ProductCode) -or $ProductCode -match '<[^>]+>') { $ProductCode = Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues['ProductCode']) -SymbolValues $SymbolValues }
  if ([string]::IsNullOrWhiteSpace($ProductCode) -or $ProductCode -match '<[^>]+>') { $ProductCode = $null }
  $DefaultInstallLocation = Resolve-InstallMateManifestValue -Value ([string]$SymbolValues[$PrimaryFolderName]) -SymbolValues $SymbolValues
  if ([string]::IsNullOrWhiteSpace($DefaultInstallLocation) -or $DefaultInstallLocation -match '<[^>]+>') {
    $PrimaryFolder = @($Folders | Where-Object Name -EQ $PrimaryFolderName | Select-Object -First 1)
    $DefaultInstallLocation = $PrimaryFolder.Count -eq 1 ? [string]$PrimaryFolder[0].ResolvedPath : $null
  }
  [pscustomobject]@{
    DatabaseSignature    = $Database.DatabaseSignature
    DatabaseLength       = $Database.Length
    InstallRecordOffset  = $InstallRecordOffset
    InstallLevel         = $InstallLevel
    FileLayoutSupported  = $FileLayoutSupported
    FileRecords          = $FileRecords
    Components           = $Components
    Folders              = $Folders
    RegistryKeys         = $RegistryKeys
    RegistryValueRecords = $RegistryValueRecords
    EnvironmentChanges   = $EnvironmentRecords
    Shortcuts            = $SystemEffects.Shortcuts
    ExecutionActions     = $SystemEffects.ExecutionActions
    Prerequisites        = $SystemEffects.Prerequisites
    Services             = $SystemEffects.Services
    ServiceActions       = $SystemEffects.ServiceActions
    InstallRecords       = $InstallRecords
    InstallRecord        = $InstallRecord
    SymbolRecords        = $SymbolRecords
    Symbols              = $SymbolValues
    Metadata             = [pscustomobject]@{
      ProductCode            = $ProductCode
      ProductName            = Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues['ProductName']) -SymbolValues $SymbolValues
      ProductVersion         = Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues['ProductVersion']) -SymbolValues $SymbolValues
      PackageCode            = Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues['PackageCode']) -SymbolValues $SymbolValues
      UninstallKey           = Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues['UninstallKey']) -SymbolValues $SymbolValues
      PrimaryFolder          = $PrimaryFolderName
      InstallDirectory       = Resolve-InstallMateManifestValue -Value ([string]$SymbolValues['INSTALLDIR']) -SymbolValues $SymbolValues
      Publisher              = Resolve-InstallMateSymbolValue -Value ([string]$SymbolValues['Publisher']) -SymbolValues $SymbolValues
      DefaultInstallLocation = $DefaultInstallLocation
      Scope                  = $null
    }
  }
}

function Get-InstallMateArchiveInfo {
  <#
  .SYNOPSIS
    Locate and select the package-bearing Tarma TIZ archive
  .DESCRIPTION
    Legacy media starts with TIZ1 at the PE overlay. Newer compressed EXEs can
    contain more than one TIZ3 stream, while builder installers host TIZ3/TIZ4
    at +0x10 in .tsustub and .tsuarch. Each candidate is range-validated and
    decoded just far enough to identify Setup.ini or a type-2 tin database.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Layout = Get-PELayout -Path $File.FullName
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $Candidates = [Collections.Generic.List[object]]::new()
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    $CertificateDirectory = $Layout.DataDirectories['Certificate']
    $PhysicalEnd = if ($CertificateDirectory -and $CertificateDirectory.Rva -gt 0 -and $CertificateDirectory.Rva -le $Stream.Length) { [long]$CertificateDirectory.Rva } else { [long]$Stream.Length }

    # TIZ1 is authenticated only at the exact PE overlay boundary. Its compact
    # header is followed directly by an RFC1950 zlib member.
    if ($OverlayOffset -gt 0 -and $OverlayOffset + 10 -le $PhysicalEnd) {
      $LegacyHeader = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 10
      $CmfFlg = ([int]$LegacyHeader[8] -shl 8) -bor $LegacyHeader[9]
      if ([Text.Encoding]::ASCII.GetString($LegacyHeader, 0, 4) -ceq 'tiz1' -and [BitConverter]::ToUInt32($LegacyHeader, 4) -eq 1 -and ($LegacyHeader[8] -band 0x0F) -eq 8 -and $CmfFlg % 31 -eq 0) {
        $Candidates.Add([pscustomobject][ordered]@{
            Signature = 'tiz1'; FormatMajor = [uint16]1; FormatMinor = [uint16]0; FormatVersion = '1.0'; BuilderFormatVersion = $null
            ArchiveOffset = [long]$OverlayOffset; ContainerRoute = 'Overlay'; ContainerEndOffset = $PhysicalEnd; DataEndOffset = $PhysicalEnd
            DataOffset = [long]$OverlayOffset + 8; PropertiesOffset = $null; PropertiesLength = 0; CompressionAlgorithm = 'Zlib'
            DeclaredArchiveSize = $null; AvailableArchiveBytes = [uint64]($PhysicalEnd - $OverlayOffset); CertificateOffset = $PhysicalEnd -lt $File.Length ? $PhysicalEnd : $null
            IsComplete = $true; IsPackageArchive = $null; ProbeError = $null
          })
      }
    }

    # Modern overlay headers may follow an embedded loader archive. Search only
    # the bounded overlay prefix; markers compiled into PE code sections are not
    # candidates.
    $Locations = [Collections.Generic.List[object]]::new()
    if ($OverlayOffset -gt 0 -and $PhysicalEnd - $OverlayOffset -ge $Script:InstallMateMinimumHeaderBytes) {
      $ScanLength = [Math]::Min($Script:InstallMateMaximumHeaderScanBytes, $PhysicalEnd - $OverlayOffset)
      foreach ($SignatureText in 'tiz2', 'tiz3', 'tiz4') {
        foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern ([Text.Encoding]::ASCII.GetBytes($SignatureText)) -StartOffset $OverlayOffset -Length $ScanLength -Maximum $Script:InstallMateMaximumArchiveCandidates)) {
          $Locations.Add([pscustomobject]@{ Signature = $SignatureText; Offset = [long]$Offset; Route = 'Overlay'; End = $PhysicalEnd })
        }
      }
    }

    # Builder installers use exact section-relative positions instead of a PE
    # overlay. Restricting candidates to +0x10 avoids arbitrary section scans.
    foreach ($Section in @($Layout.Sections | Where-Object Name -In '.tsustub', '.tsuarch')) {
      $Offset = [long]$Section.RawOffset + 0x10
      $End = [Math]::Min($PhysicalEnd, [long]$Section.RawOffset + [long]$Section.RawSize)
      if ($Offset + 4 -gt $End) { continue }
      $SignatureText = [Text.Encoding]::ASCII.GetString((Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 4))
      if ($SignatureText -in 'tiz2', 'tiz3', 'tiz4') { $Locations.Add([pscustomobject]@{ Signature = $SignatureText; Offset = $Offset; Route = "Section:$($Section.Name)"; End = $End }) }
    }

    $SeenOffsets = [Collections.Generic.HashSet[long]]::new()
    foreach ($Location in @($Locations | Sort-Object Offset)) {
      if (-not $SeenOffsets.Add([long]$Location.Offset) -or $Location.Offset + $Script:InstallMateMinimumHeaderBytes -gt $Location.End) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $Location.Offset -Count $Script:InstallMateMinimumHeaderBytes
      $FormatMajor = [BitConverter]::ToUInt16($Header, 4)
      $FormatMinor = [BitConverter]::ToUInt16($Header, 6)
      $Reserved = [BitConverter]::ToUInt64($Header, 8)
      $DeclaredArchiveSize = [BitConverter]::ToUInt64($Header, 16)
      $AvailableContainerBytes = [uint64]($Location.End - $Location.Offset)
      if ($FormatMajor -eq 0 -or $FormatMajor -gt 4096 -or $FormatMinor -gt 4096 -or $Reserved -ne 0) { continue }
      if ($DeclaredArchiveSize -lt $Script:InstallMateMinimumHeaderBytes -or $DeclaredArchiveSize -gt $AvailableContainerBytes + 64) { continue }
      $DeclaredEnd = [long][Math]::Min([decimal]$Location.End, [decimal]$Location.Offset + [decimal]$DeclaredArchiveSize)
      # Controlled InstallMate 11 builds map the builder's Deflate, LZMA, and
      # LZMA2 choices to tiz2, tiz3, and tiz4 respectively. TIZ2 has no property
      # block and begins with an RFC 1950 CMF/FLG pair at archive-relative +0x38.
      $PropertiesLength = switch ($Location.Signature) { 'tiz2' { 0 } 'tiz3' { 5 } 'tiz4' { 1 } }
      $DataOffset = [long]$Location.Offset + 0x38 + $PropertiesLength
      if ($DataOffset -ge $DeclaredEnd) { continue }
      if ($Location.Signature -ceq 'tiz2') {
        $ZlibHeader = Read-BinaryBytes -Stream $Stream -Offset $DataOffset -Count 2
        $CmfFlg = ([int]$ZlibHeader[0] -shl 8) -bor $ZlibHeader[1]
        if (($ZlibHeader[0] -band 0x0F) -ne 8 -or $CmfFlg % 31 -ne 0) { continue }
      }
      $Candidates.Add([pscustomobject][ordered]@{
          Signature = $Location.Signature; FormatMajor = [uint16]$FormatMajor; FormatMinor = [uint16]$FormatMinor; FormatVersion = "$FormatMajor.$FormatMinor"; BuilderFormatVersion = "$FormatMinor.$FormatMajor"
          ArchiveOffset = [long]$Location.Offset; ContainerRoute = $Location.Route; ContainerEndOffset = [long]$Location.End; DataEndOffset = $DeclaredEnd
          DataOffset = $DataOffset; PropertiesOffset = [long]$Location.Offset + 0x38; PropertiesLength = $PropertiesLength
          CompressionAlgorithm = switch ($Location.Signature) { 'tiz2' { 'Zlib' } 'tiz3' { 'Lzma' } 'tiz4' { 'Lzma2' } }
          DeclaredArchiveSize = $DeclaredArchiveSize; AvailableArchiveBytes = [uint64]($DeclaredEnd - $Location.Offset); CertificateOffset = $PhysicalEnd -lt $File.Length ? $PhysicalEnd : $null
          IsComplete = $DeclaredArchiveSize -le $AvailableContainerBytes + 64; IsPackageArchive = $null; ProbeError = $null
        })
    }
  } finally { $Stream.Dispose() }

  if ($Candidates.Count -eq 0) { throw 'The PE does not contain a structurally valid InstallMate TIZ archive.' }
  $SupportedCandidates = @($Candidates | Where-Object CompressionAlgorithm)

  # A single structurally valid archive needs no second decompression pass.
  # Multiple candidates are probed only through the first decoded record to
  # distinguish observed type-8/9 loader archives from the type-2 package.
  foreach ($Candidate in @($SupportedCandidates.Count -gt 1 ? $SupportedCandidates : @())) {
    $Context = $null
    try {
      $Context = Open-InstallMateDecoderContext -Path $File.FullName -ArchiveInfo $Candidate
      if ($Candidate.Signature -ceq 'tiz1') {
        $Record = Read-InstallMateLegacyRecordHeader -Decoder $Context.Decoder
        $Candidate.IsPackageArchive = $Record.Name -ceq 'Setup.ini'
      } else {
        $Header = Read-InstallMateSequentialRecord -Stream $Context.Decoder -Count 64
        if ([Text.Encoding]::ASCII.GetString($Header, 0, 4) -cne 'tzf3' -or [BitConverter]::ToUInt16($Header, 8) -ne 2) { continue }
        $DatabaseSignature = [Text.Encoding]::ASCII.GetString((Read-InstallMateSequentialRecord -Stream $Context.Decoder -Count 4))
        $Candidate.IsPackageArchive = $DatabaseSignature -match '^tin[A-Za-z0-9]$'
      }
    } catch { $Candidate.ProbeError = $_.Exception.Message }
    finally { if ($Context) { Close-InstallMateDecoderContext -Context $Context } }
  }

  if ($SupportedCandidates.Count -eq 1) {
    $Selected = $SupportedCandidates[0]
  } else {
    $PackageCandidates = @($SupportedCandidates | Where-Object IsPackageArchive)
    if ($PackageCandidates.Count -gt 1) { throw 'More than one InstallMate archive contains a setup database; package selection is ambiguous.' }
    if ($PackageCandidates.Count -eq 0) { throw 'No package database could be selected from the multiple InstallMate archives.' }
    $Selected = $PackageCandidates[0]
  }
  $Selected | Add-Member -NotePropertyName ArchiveCandidates -NotePropertyValue @($Candidates | ForEach-Object {
      [pscustomobject]@{ Signature = $_.Signature; Offset = $_.ArchiveOffset; ContainerRoute = $_.ContainerRoute; CompressionAlgorithm = $_.CompressionAlgorithm; IsPackageArchive = $_.IsPackageArchive; ProbeError = $_.ProbeError }
    }) -Force
  return $Selected
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
    # PE values are useful fallbacks, but Setup.ini and typed tin symbols are
    # closer to the runtime's ARP identity and therefore take precedence.
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $VersionStrings = Get-PEVersionStringTable -Path $File.FullName -ErrorAction SilentlyContinue
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    $Diagnostics = [Collections.Generic.List[object]]::new()
    $Unresolved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $DatabaseInfo = $null
    try {
      $DatabaseInfo = if ($ArchiveInfo.Signature -ceq 'tiz1') { Read-InstallMateLegacyDatabaseInfo -Path $File.FullName -ArchiveInfo $ArchiveInfo } else { Read-InstallMateDatabaseInfo -Path $File.FullName -ArchiveInfo $ArchiveInfo }
    } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Database.DecodeFailed' -Source InstallMate -Message "The InstallMate setup database could not be decoded: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata, Extraction -AffectedFields ProductCode, AppsAndFeaturesEntries))
    }

    $Metadata = $DatabaseInfo ? $DatabaseInfo.Metadata : [pscustomobject]@{
      ProductCode = $null; ProductName = $null; ProductVersion = $null; PackageCode = $null; Publisher = $null; DefaultInstallLocation = $null; Scope = $null
    }
    $PeProductCode = ([string]$VersionStrings.ProductCode).Trim()
    $ProductCode = ([string]$Metadata.ProductCode).Trim()
    $ProductCodeEvidence = if ($ProductCode) { $ArchiveInfo.Signature -ceq 'tiz1' ? 'Setup.ini uninstall-key value' : 'Typed tin symbol record and resolved UninstallKey' } else { $null }
    if ([string]::IsNullOrWhiteSpace($ProductCode)) {
      $ProductCode = [string]::IsNullOrWhiteSpace($PeProductCode) ? $null : $PeProductCode
      if ($ProductCode) { $ProductCodeEvidence = 'Named StringFileInfo.ProductCode value in the PE version resource' }
    }
    $PackageCode = ([string]$Metadata.PackageCode).Trim()
    if ([string]::IsNullOrWhiteSpace($PackageCode)) { $PackageCode = ([string]$VersionStrings.PackageCode).Trim() }
    if ([string]::IsNullOrWhiteSpace($PackageCode)) { $PackageCode = $null }
    $DisplayName = ([string]$Metadata.ProductName).Trim()
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = ([string]$VersionInfo.ProductName).Trim() }
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = ([string]$VersionInfo.FileDescription).Trim() }
    $DisplayVersion = ([string]$Metadata.ProductVersion).Trim()
    if ([string]::IsNullOrWhiteSpace($DisplayVersion)) { $DisplayVersion = ([string]$VersionInfo.ProductVersion).Trim() }
    $Publisher = ([string]$Metadata.Publisher).Trim()
    if ([string]::IsNullOrWhiteSpace($Publisher)) { $Publisher = ([string]$VersionInfo.CompanyName).Trim() }
    $DefaultInstallLocation = ([string]$Metadata.DefaultInstallLocation).Trim()
    if ([string]::IsNullOrWhiteSpace($DefaultInstallLocation)) { $DefaultInstallLocation = $null }

    if ($ArchiveInfo.Signature -ceq 'tiz1' -and $Metadata.Scope) {
      $ScopeInfo = [pscustomobject]@{ InstallLevel = $null; InstallLevelName = $null; Scope = $Metadata.Scope; DefaultScope = $Metadata.Scope; SupportedScopes = @($Metadata.Scope); SupportsDualScope = $false; Confidence = 'high'; Evidence = @('The legacy Setup.ini uninstall hive or AdminRights field establishes the installation scope.') }
    } else {
      $ScopeInfo = Get-InstallMateScopeInfo -RequestedExecutionLevel $ExecutionLevel -InstallLevel $DatabaseInfo.InstallLevel
    }
    $RegistryWrites = if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['RegistryValueRecords'] -and @($DatabaseInfo.RegistryValueRecords).Count -gt 0) {
      @(ConvertTo-InstallMateRegistryWrite -RegistryValueRecord $DatabaseInfo.RegistryValueRecords -RegistryKeyRecord $DatabaseInfo.RegistryKeys -SymbolValues $DatabaseInfo.Symbols -Scope $ScopeInfo.Scope)
    } else { @() }
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite @($RegistryWrites | Where-Object IsAuthoritative)
    $ArpProjection = if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['InstallRecord']) {
      Get-InstallMateAppsAndFeaturesProjection -InstallRecord $DatabaseInfo.InstallRecord -RegistryWrite $RegistryWrites -SymbolValues $DatabaseInfo.Symbols
    } else { [pscustomobject]@{ Entries = @(); BuiltInValues = [ordered]@{} } }
    if ($DatabaseInfo -and $ArchiveInfo.Signature -cne 'tiz1' -and $null -eq $DatabaseInfo.InstallLevel) {
      if ($ArchiveInfo.FormatMajor -lt 15) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Scope.GenerationUnmapped' -Source InstallMate -Message "InstallMate database $($ArchiveInfo.BuilderFormatVersion) was decoded, but its install-level record layout is not yet mapped; scope falls back to PE elevation evidence." -Kind Incomplete -Areas Metadata -AffectedFields Scope))
      } else {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Scope.RecordUnresolved' -Source InstallMate -Message 'The InstallMate database did not contain one unambiguous supported install-level record; scope falls back to PE elevation evidence.' -Kind Incomplete -Areas Metadata -AffectedFields Scope))
      }
    }
    if ($ScopeInfo.SupportsDualScope) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Scope.ElevationDependent' -Source InstallMate -Message 'This InstallMate package has elevation-dependent scope; confirm whether its command line can select scope before creating duplicate installer entries.' -Kind ManualValidation -Areas Metadata, Installability -AffectedFields Scope))
    }
    if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['FileLayoutSupported'] -and -not $DatabaseInfo.FileLayoutSupported) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Extraction.DatabaseRevisionUnmapped' -Source InstallMate -Message "The $($DatabaseInfo.DatabaseSignature) file-record revision used by InstallMate $($ArchiveInfo.BuilderFormatVersion) is not mapped; metadata remains available but installed payload paths are unresolved." -Kind Unsupported -Areas Extraction -AffectedFields ExtractedFiles))
    }
    if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['RegistryValueRecords'] -and @($DatabaseInfo.RegistryValueRecords).Count -gt @($RegistryWrites).Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Registry.RecordUnresolved' -Source InstallMate -Message 'One or more InstallMate registry-value records could not be resolved to a literal registry key; affected custom ARP or association evidence requires VM validation.' -Kind Incomplete -Areas Metadata -AffectedFields AppsAndFeaturesEntries, Protocols, FileExtensions))
    }
    if (@($RegistryWrites | Where-Object { $_.Complete -and -not $_.IsAuthoritative -and $_.IsConditional }).Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Registry.ComponentConditional' -Source InstallMate -Message 'One or more literal InstallMate registry writes belong to a conditional component and are retained as evidence without being promoted to ARP or association metadata.' -Kind Ambiguous -Areas Metadata -AffectedFields AppsAndFeaturesEntries, Protocols, FileExtensions))
    }
    if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Components']) {
      $ComponentOwnedRecords = @($DatabaseInfo.FileRecords) + @($DatabaseInfo.Folders) + @($DatabaseInfo.RegistryValueRecords) + @($DatabaseInfo.EnvironmentChanges) + @($DatabaseInfo.Shortcuts) + @($DatabaseInfo.Services) + @($DatabaseInfo.ServiceActions)
      if (@($ComponentOwnedRecords | Where-Object { $_.PSObject.Properties['UnresolvedComponentKeys'] -and @($_.UnresolvedComponentKeys).Count -gt 0 }).Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Component.ReferenceUnresolved' -Source InstallMate -Message 'One or more InstallMate records reference a component that was not decoded; affected files or system effects remain non-authoritative.' -Kind Incomplete -Areas Metadata, Extraction -AffectedFields ExtractedFiles, AppsAndFeaturesEntries, Protocols, FileExtensions))
      }
    }
    if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['EnvironmentChanges']) {
      $UnresolvedEnvironmentChanges = @($DatabaseInfo.EnvironmentChanges | Where-Object { -not $_.ConfigurationComplete })
      if ($UnresolvedEnvironmentChanges.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Environment.ConfigurationPartiallyDecoded' -Source InstallMate -Message 'One or more InstallMate environment-variable records contain operation values outside the verified current-format domains.' -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallationMetadata -Evidence ([pscustomobject]@{ VariableNames = [string[]]@($UnresolvedEnvironmentChanges.Name) })))
      }
    }
    if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Prerequisites'] -and @($DatabaseInfo.Prerequisites | Where-Object RequiresAdministrator).Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Prerequisite.RequiresAdministrator' -Source InstallMate -Message 'One or more selected InstallMate prerequisite handlers require Administrator rights. Confirm the prerequisite condition and silent elevation behavior before authoring ElevationRequirement.' -Kind ManualValidation -Areas Installability -AffectedFields ElevationRequirement, Dependencies))
    }
    if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Services']) {
      $UnresolvedServices = @($DatabaseInfo.Services | Where-Object {
          -not $_.TargetFileResolved -or -not $_.ServiceTypeName -or -not $_.StartTypeName -or -not $_.ErrorControlName -or $_.RecoveryActionCount -ne @($_.RecoveryActions).Count -or @($_.RecoveryActions | Where-Object { -not $_.Action }).Count -gt 0
        })
      if ($UnresolvedServices.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.Service.ConfigurationPartiallyDecoded' -Source InstallMate -Message 'One or more InstallMate service records contain an unresolved target, control value, or recovery-action list.' -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallationMetadata -Evidence ([pscustomobject]@{ ServiceNames = [string[]]@($UnresolvedServices.Name) })))
      }
    }
    if ($DatabaseInfo -and $DatabaseInfo.PSObject.Properties['ServiceActions']) {
      $UnresolvedServiceActions = @($DatabaseInfo.ServiceActions | Where-Object { -not $_.ConfigurationComplete })
      if ($UnresolvedServiceActions.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallMate.ServiceAction.ConfigurationPartiallyDecoded' -Source InstallMate -Message 'One or more InstallMate service-control records contain an action value outside the verified current-format domain.' -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallationMetadata -Evidence ([pscustomobject]@{ ServiceNames = [string[]]@($UnresolvedServiceActions.Name) })))
      }
    }
    if (-not $ProductCode) { $null = $Unresolved.Add('ProductCode') }
    if (-not $ScopeInfo.Scope) { $null = $Unresolved.Add('Scope') }
    if (-not $DefaultInstallLocation) { $null = $Unresolved.Add('DefaultInstallLocation') }
    $AppsAndFeaturesEntries = if ($ArchiveInfo.Signature -ceq 'tiz1' -and $ProductCode) {
      $Entry = [ordered]@{ ProductCode = $ProductCode; InstallerType = 'exe' }
      if ($DisplayName) { $Entry['DisplayName'] = $DisplayName }
      if ($DisplayVersion) { $Entry['DisplayVersion'] = $DisplayVersion }
      if ($Publisher) { $Entry['Publisher'] = $Publisher }
      @([pscustomobject]$Entry)
    } else { @($ArpProjection.Entries) }
    $WritesAppsAndFeaturesEntry = $AppsAndFeaturesEntries.Count -gt 0
    $AppsAndFeaturesProductCode = $AppsAndFeaturesEntries.Count -eq 1 ? [string]$AppsAndFeaturesEntries[0].ProductCode : $null
    $CanExpand = $null -ne $DatabaseInfo -and (-not $DatabaseInfo.PSObject.Properties['FileLayoutSupported'] -or [bool]$DatabaseInfo.FileLayoutSupported)

    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $DisplayVersion
      Publisher                    = $Publisher
      Scope                        = $ScopeInfo.Scope
      DefaultInstallLocation       = $DefaultInstallLocation
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $AppsAndFeaturesProductCode
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($Unresolved | Sort-Object)
      Family                       = 'InstallMate'
      ProductCodeEvidence          = $ProductCodeEvidence
      PackageCode                  = $PackageCode
      FileDescription              = ([string]$VersionInfo.FileDescription).Trim()
      DefaultScope                 = $ScopeInfo.DefaultScope
      SupportedScopes              = $ScopeInfo.SupportedScopes
      SupportsDualScope            = $ScopeInfo.SupportsDualScope
      ScopeConfidence              = $ScopeInfo.Confidence
      ScopeEvidence                = $ScopeInfo.Evidence
      InstallLevel                 = $ScopeInfo.InstallLevel
      InstallLevelName             = $ScopeInfo.InstallLevelName
      RequestedExecutionLevel      = $ExecutionLevel
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      AppsAndFeaturesEntries       = $AppsAndFeaturesEntries
      AppsAndFeaturesValues        = $ArpProjection.BuiltInValues
      RegistryHive                 = if ($ScopeInfo.Scope -eq 'machine') { 'HKLM' } elseif ($ScopeInfo.Scope -eq 'user') { 'HKCU' } else { $null }
      RegistryView                 = $null
      InstallerSwitches            = [ordered]@{ Silent = '/q2 /b0'; SilentWithProgress = '/q1 /b0'; InstallLocation = '"INSTALLDIR=<INSTALLPATH>"'; Log = '/log:"<LOGPATH>"' }
      InstallModes                 = @('interactive', 'silent', 'silentWithProgress')
      InstallerSuccessCodes        = @()
      ArchiveInfo                  = $ArchiveInfo
      DatabaseInfo                 = if ($DatabaseInfo) {
        [pscustomobject]@{
          Signature           = $DatabaseInfo.DatabaseSignature
          Length              = $DatabaseInfo.DatabaseLength
          InstallRecordOffset = $DatabaseInfo.InstallRecordOffset
          FileRecordCount     = $DatabaseInfo.FileRecords.Count
          SymbolRecordCount   = @($DatabaseInfo.SymbolRecords).Count
          FileLayoutSupported = $DatabaseInfo.PSObject.Properties['FileLayoutSupported'] ? $DatabaseInfo.FileLayoutSupported : $true
        }
      } else { $null }
      Symbols                      = $DatabaseInfo ? $DatabaseInfo.Symbols : [ordered]@{}
      Components                   = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Components'] ? $DatabaseInfo.Components : @()
      Folders                      = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Folders'] ? $DatabaseInfo.Folders : @()
      RegistryValueRecords         = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['RegistryValueRecords'] ? $DatabaseInfo.RegistryValueRecords : @()
      EnvironmentChanges           = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['EnvironmentChanges'] ? $DatabaseInfo.EnvironmentChanges : @()
      Shortcuts                    = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Shortcuts'] ? $DatabaseInfo.Shortcuts : @()
      ExecutionActions             = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['ExecutionActions'] ? $DatabaseInfo.ExecutionActions : @()
      Prerequisites                = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Prerequisites'] ? $DatabaseInfo.Prerequisites : @()
      Services                     = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['Services'] ? $DatabaseInfo.Services : @()
      ServiceActions               = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['ServiceActions'] ? $DatabaseInfo.ServiceActions : @()
      PackageDownloadUrl           = $DatabaseInfo -and $DatabaseInfo.PSObject.Properties['InstallRecord'] -and $DatabaseInfo.InstallRecord ? $DatabaseInfo.InstallRecord.PackageDownloadUrl : $null
      FileEntries                  = if ($DatabaseInfo) { $DatabaseInfo.FileRecords } else { @() }
      ExtractedFiles               = if ($DatabaseInfo) { @($DatabaseInfo.FileRecords | ForEach-Object { $_.RelativePath ? $_.RelativePath : $_.FileName }) } else { @() }
      CanExpand                    = $CanExpand
      FormatGeneration             = $ArchiveInfo.Signature -ceq 'tiz1' ? 'Legacy2' : 'Modern'
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallMate'; ParserMajor = 6; Sources = @('PE version resource and application manifest', 'bounded TIZ1 zlib/tzff Setup.ini records', 'bounded TIZ2 zlib records', 'bounded TIZ3 raw-LZMA records', 'bounded TIZ4 raw-LZMA2 records', 'typed tin symbol, package, folder, file, registry, environment, shortcut, execution, prerequisite, service, and service-control records', 'InstallMate shipped symbol definitions and setup documentation') }
    }
  }
}

function Expand-InstallMateInstaller {
  <#
  .SYNOPSIS
    Expand bounded files from an InstallMate TIZ package without executing setup
  .DESCRIPTION
    Legacy Setup.ini media is expanded to its explicit Files-group destination.
    Current databases use their decoded folder graph. Older modern records whose
    folder layout is unavailable fall back to Payload/<record-key>/<file-name>.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [AllowEmptyString()][string]$Name,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallMate-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $ArchiveInfo = Get-InstallMateArchiveInfo -Path $File.FullName
    $Context = Open-InstallMateDecoderContext -Path $File.FullName -ArchiveInfo $ArchiveInfo
    $Results = [Collections.Generic.List[object]]::new()
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
      if ($ArchiveInfo.Signature -ceq 'tiz1') {
        # Consume Setup.ini once, preserving its repeated Files groups, then
        # stream only selected tzff payload records to their explicit targets.
        $SetupRecord = Read-InstallMateLegacyRecordHeader -Decoder $Context.Decoder
        if ($SetupRecord.Name -cne 'Setup.ini' -or $SetupRecord.PayloadLength -gt $Script:InstallMateMaximumLegacyConfigurationBytes -or $SetupRecord.PayloadLength -gt [int]::MaxValue) { throw 'The InstallMate 2 Setup.ini record is missing or exceeds the configuration limit.' }
        $SetupBytes = Read-InstallMateSequentialRecord -Stream $Context.Decoder -Count ([int]$SetupRecord.PayloadLength)
        $Configuration = ConvertFrom-InstallMateLegacyConfiguration -Text (ConvertFrom-InstallMateLegacyText -Bytes $SetupBytes)
        $Outstanding = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($Record in $Configuration.FileRecords) { if (-not $Outstanding.ContainsKey($Record.ArchivePath)) { $Outstanding.Add($Record.ArchivePath, $Record) } }
        $SelectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($Record in $Configuration.FileRecords) {
          if (-not $PSBoundParameters.ContainsKey('Name') -or (Test-ExtractionPattern -Path $Record.RelativePath -Pattern $Name) -or (Test-ExtractionPattern -Path $Record.ArchivePath -Pattern $Name)) { $null = $SelectedPaths.Add($Record.ArchivePath) }
        }
        $DecodedBytes = $SetupRecord.PayloadLength + $Script:InstallMateLegacyHeaderBytes + $SetupRecord.NameLength
        $RecordCount = 1
        while ($SelectedPaths.Count -gt 0) {
          if (++$RecordCount -gt $Script:InstallMateMaximumFileRecords + 1) { throw 'The InstallMate 2 package exceeds the record-count limit.' }
          $PayloadRecord = Read-InstallMateLegacyRecordHeader -Decoder $Context.Decoder
          if ($DecodedBytes + $Script:InstallMateLegacyHeaderBytes + $PayloadRecord.NameLength + $PayloadRecord.PayloadLength -gt $MaximumExpandedBytes) { throw "The InstallMate decoded stream exceeds the $MaximumExpandedBytes-byte output limit." }
          $CatalogRecord = $Outstanding.ContainsKey($PayloadRecord.Name) ? $Outstanding[$PayloadRecord.Name] : $null
          if ($CatalogRecord -and $CatalogRecord.UncompressedSize -ne $PayloadRecord.PayloadLength) { throw "InstallMate 2 payload '$($PayloadRecord.Name)' does not match its declared file size." }
          $IsSelected = $CatalogRecord -and $SelectedPaths.Contains($PayloadRecord.Name)
          if ($IsSelected) {
            $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $CatalogRecord.RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
            if ($Target.ShouldWrite) {
              $Parent = [IO.Path]::GetDirectoryName($Target.Path)
              if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
              $Output = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
              try { $null = Copy-BoundedStream -Source $Context.Decoder -Destination $Output -MaximumBytes $PayloadRecord.PayloadLength -ExpectedBytes $PayloadRecord.PayloadLength }
              finally { $Output.Dispose() }
              $Results.Add((Get-Item -LiteralPath $Target.Path -Force))
            } else {
              $null = Copy-BoundedStream -Source $Context.Decoder -Destination ([IO.Stream]::Null) -MaximumBytes $PayloadRecord.PayloadLength -ExpectedBytes $PayloadRecord.PayloadLength
            }
            $null = $SelectedPaths.Remove($PayloadRecord.Name)
          } else {
            $null = Copy-BoundedStream -Source $Context.Decoder -Destination ([IO.Stream]::Null) -MaximumBytes $PayloadRecord.PayloadLength -ExpectedBytes $PayloadRecord.PayloadLength
          }
          if ($CatalogRecord) { $null = $Outstanding.Remove($PayloadRecord.Name) }
          $DecodedBytes += $Script:InstallMateLegacyHeaderBytes + $PayloadRecord.NameLength + $PayloadRecord.PayloadLength
        }
        return $Results.ToArray()
      }

      # Decode the catalog once, then match sequential tzf3 payload segments by
      # their structured type and uncompressed size rather than physical names.
      $Database = Read-InstallMateDatabaseSegment -Decoder $Context.Decoder
      if (-not (Test-InstallMateFileLayoutSupported -DatabaseSignature $Database.DatabaseSignature -FormatMajor $ArchiveInfo.FormatMajor)) {
        throw "The $($Database.DatabaseSignature) file-record revision used by InstallMate $($ArchiveInfo.BuilderFormatVersion) is not supported for extraction."
      }
      $RawRecords = @(Get-InstallMateFileRecord -Database $Database.Bytes -DatabaseSignature $Database.DatabaseSignature -FormatMajor $ArchiveInfo.FormatMajor)
      if ($Database.DatabaseSignature -in 'tin9', 'tinA', 'tinB' -and $RawRecords.Count -gt 0) {
        $SymbolRecords = @(Get-InstallMateSymbolRecord -Database $Database.Bytes -DatabaseSignature $Database.DatabaseSignature)
        $SymbolValues = [ordered]@{}
        foreach ($Symbol in $SymbolRecords) { if (-not [string]::IsNullOrWhiteSpace($Symbol.Name)) { $SymbolValues[$Symbol.Name] = $Symbol.Value } }
        $Folders = @(Resolve-InstallMateFolderGraph -FolderRecord @(Get-InstallMateFolderRecord -Database $Database.Bytes) -SymbolValues $SymbolValues)
        $PrimaryFolderName = ([string]$SymbolValues['PRIMARYFOLDER']).Trim([char[]]@('<', '>'))
        if ([string]::IsNullOrWhiteSpace($PrimaryFolderName)) { $PrimaryFolderName = 'INSTALLDIR' }
        $RawRecords = @(Resolve-InstallMateInstalledFilePath -FileRecord $RawRecords -FolderRecord $Folders -PrimaryFolderName $PrimaryFolderName)
      }
      $Outstanding = [Collections.Generic.List[object]]::new()
      foreach ($Record in $RawRecords) { $Outstanding.Add($Record) }
      $Selected = if ($PSBoundParameters.ContainsKey('Name')) {
        @($Outstanding | Where-Object {
            (Test-ExtractionPattern -Path ($_.RelativePath ? $_.RelativePath : "Payload/$($_.Key)/$($_.FileName)") -Pattern $Name) -or
            (Test-ExtractionPattern -Path "Payload/$($_.Key)/$($_.FileName)" -Pattern $Name) -or
            (Test-ExtractionPattern -Path $_.FileName -Pattern $Name)
          })
      } else { @($Outstanding) }
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
        $RecordPath = $Record -and $Record.RelativePath ? $Record.RelativePath : ($Record ? "Payload/$($Record.Key)/$($Record.FileName)" : $null)
        $IsSelected = $null -ne $Record -and (-not $PSBoundParameters.ContainsKey('Name') -or
          (Test-ExtractionPattern -Path $RecordPath -Pattern $Name) -or
          (Test-ExtractionPattern -Path "Payload/$($Record.Key)/$($Record.FileName)" -Pattern $Name) -or
          (Test-ExtractionPattern -Path $Record.FileName -Pattern $Name))
        if ($IsSelected) {
          $RelativePath = $RecordPath
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
            -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if ($Target.ShouldWrite) {
            $Parent = [IO.Path]::GetDirectoryName($Target.Path)
            if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
            $Output = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
            try { $null = Copy-BoundedStream -Source $Context.Decoder -Destination $Output -MaximumBytes ([long]$SegmentLength) -ExpectedBytes ([long]$SegmentLength) }
            finally { $Output.Dispose() }
            $Results.Add((Get-Item -LiteralPath $Target.Path -Force))
          } else {
            $null = Copy-BoundedStream -Source $Context.Decoder -Destination ([IO.Stream]::Null) -MaximumBytes ([long]$SegmentLength) -ExpectedBytes ([long]$SegmentLength)
          }
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
