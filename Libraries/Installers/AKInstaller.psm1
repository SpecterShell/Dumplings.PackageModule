# SPDX-License-Identifier: Apache-2.0
# Format sources: https://www.akapplications.com/products/akinstaller/index.html
#                 https://www.akapplications.com/products/akinstallermsi/index.html
#
# AKInstaller media consumed by this parser:
#
#   native setup.exe (modern and legacy table encodings)
#   +-- PE runtime
#   `-- overlay
#       +-- encrypted ZIP (opaque Axx entries)
#       |   +-- A01: STPSETUPVERSION compiled project table
#       |   +-- STPLC rows map installed names to archive entries
#       |   `-- STPLD rows describe literal registry writes and ARP values
#       +-- XOR-protected password/configuration
#       +-- 7 little-endian uint32 footer fields
#       `-- ">AKINST_SETUP<" (RC4 table) or ">KAPI_SETUP<" (XOR table)
#
#   classic native setup.exe (observed 2005-2006 product media)
#   +-- PE runtime
#   `-- overlay
#       +-- legacy loader data
#       +-- consecutive GZip members
#       |   +-- UI/runtime resources
#       |   +-- installed and support files
#       |   `-- STPSETUPVERSION compiled project table
#       +-- UInt32 entry count + repeated 9/11-byte member descriptors
#       +-- 6 little-endian uint32 footer fields
#       `-- ">KAPI_SETUP<"
#
#   AKInstallerMSI bootstrapper
#   +-- PE runtime
#   +-- ZipCrypto ZIP
#   |   +-- Config.ini_: package and launch configuration
#   |   `-- FileN<name>_: MSI and prerequisite payloads
#   |   `-- historical central records use "AKI\x02" in place of "PK\x01\x02"
#   +-- XOR-protected password and secondary string
#   +-- 4 little-endian uint32 footer fields
#   `-- ">INSTALLMSI_SETUP<"
#
# A less common AKInstallerMSI route appends one MSI compound file directly to
# the PE. That route is accepted only when the nested MSI's CreatingApp field
# identifies AKInstallerMSI. Passwords are retained only in private contexts.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:AKInstallerNativeMarker = [Text.Encoding]::ASCII.GetBytes('>AKINST_SETUP<')
$Script:AKInstallerLegacyNativeMarker = [Text.Encoding]::ASCII.GetBytes('>KAPI_SETUP<')
$Script:AKInstallerMsiMarker = [Text.Encoding]::ASCII.GetBytes('>INSTALLMSI_SETUP<')
$Script:AKInstallerCfbMarker = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
$Script:AKInstallerZipEocdMarker = [byte[]](0x50, 0x4B, 0x05, 0x06)
$Script:AKInstallerLegacyCentralMarker = [byte[]](0x41, 0x4B, 0x49, 0x02)
$Script:AKInstallerTableKey = [Convert]::FromHexString('808086C78577053E7E2D7FDFCA442CC3')
$Script:AKInstallerMaximumTableBytes = 16777216
$Script:AKInstallerMaximumEntries = 65536
$Script:AKInstallerMaximumExpandedBytes = 4294967296

function ConvertFrom-AKInstallerRc4 {
  <#
  .SYNOPSIS
    Decode one AKInstaller compiled-table value with the runtime-derived RC4 key.
  .PARAMETER Bytes
    Ciphertext bytes from a bounded A01 record.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  $State = [int[]](0..255)
  $J = 0
  for ($Index = 0; $Index -lt 256; $Index++) {
    $J = ($J + $State[$Index] + $Script:AKInstallerTableKey[$Index % $Script:AKInstallerTableKey.Length]) -band 255
    $Temporary = $State[$Index]; $State[$Index] = $State[$J]; $State[$J] = $Temporary
  }
  $Output = [byte[]]::new($Bytes.Length)
  $I = 0; $J = 0
  for ($Index = 0; $Index -lt $Bytes.Length; $Index++) {
    $I = ($I + 1) -band 255
    $J = ($J + $State[$I]) -band 255
    $Temporary = $State[$I]; $State[$I] = $State[$J]; $State[$J] = $Temporary
    $Output[$Index] = $Bytes[$Index] -bxor $State[($State[$I] + $State[$J]) -band 255]
  }
  return , $Output
}

function ConvertFrom-AKInstallerTableString {
  <#
  .SYNOPSIS
    Decode a compiled UTF-16LE or raw string table value.
  .PARAMETER Bytes
    Plain or RC4-decoded record bytes.
  .PARAMETER TableProfile
    Source-backed string encoding selected by the validated outer container route.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
    [ValidateSet('ModernRc4', 'LegacyXor')][string]$TableProfile = 'ModernRc4'
  )

  if ($Bytes.Length -eq 0) { return '' }
  if ($TableProfile -ceq 'LegacyXor') { return [Text.Encoding]::GetEncoding(1252).GetString($Bytes).TrimEnd([char]0) }
  $LooksUnicode = $Bytes.Length % 2 -eq 0
  if ($LooksUnicode) {
    for ($Index = 1; $Index -lt $Bytes.Length; $Index += 2) {
      if ($Bytes[$Index] -ne 0) { $LooksUnicode = $false; break }
    }
  }
  $Encoding = $LooksUnicode ? [Text.Encoding]::Unicode : [Text.Encoding]::UTF8
  return $Encoding.GetString($Bytes).TrimEnd([char]0)
}

function Read-AKInstallerTableCell {
  <#
  .SYNOPSIS
    Read one bounded typed value from an AKInstaller A01 table.
  .PARAMETER Bytes
    Complete bounded A01 table bytes.
  .PARAMETER Offset
    Record-relative offset of the one-byte type tag.
  .PARAMETER TableProfile
    Source-backed string transform selected by the validated outer container route.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset,
    [ValidateSet('ModernRc4', 'LegacyXor')][string]$TableProfile = 'ModernRc4'
  )

  if ($Offset + 5 -gt $Bytes.Length) { throw 'The AKInstaller table cell header is truncated.' }
  $Type = [int]$Bytes[$Offset]
  $Field = [BitConverter]::ToUInt32($Bytes, $Offset + 1)
  switch ($Type) {
    { $_ -in 1, 2, 5 } {
      if ($Field -gt $Script:AKInstallerMaximumTableBytes -or $Offset + 5L + $Field + 1L -gt $Bytes.Length) { throw 'The AKInstaller table string range is malformed.' }
      $Data = [byte[]]::new([int]$Field)
      if ($Field -gt 0) { [Array]::Copy($Bytes, $Offset + 5, $Data, 0, [int]$Field) }
      if ($Type -in 1, 2) {
        if ($TableProfile -ceq 'LegacyXor') {
          # AKInstaller 4.x applies XOR 0x7B to ordinary strings. Type 2
          # receives the runtime's second XOR 0x15, producing net XOR 0x6E.
          $Mask = $Type -eq 1 ? 0x7B : 0x6E
          for ($Index = 0; $Index -lt $Data.Length; $Index++) { $Data[$Index] = $Data[$Index] -bxor $Mask }
        } else {
          $Data = ConvertFrom-AKInstallerRc4 -Bytes $Data
        }
      }
      $Value = $Type -eq 5 ? $Data : (ConvertFrom-AKInstallerTableString -Bytes $Data -TableProfile $TableProfile)
      return [pscustomobject][ordered]@{ Type = $Type; Value = $Value; Offset = $Offset; NextOffset = [int]($Offset + 6 + $Field) }
    }
    { $_ -in 3, 4 } {
      return [pscustomobject][ordered]@{ Type = $Type; Value = [uint32]$Field; Offset = $Offset; NextOffset = $Offset + 5 }
    }
    6 {
      if ($Field -gt 1048576 -or $Offset + 5L + (4L * $Field) + 1L -gt $Bytes.Length) { throw 'The AKInstaller table integer-array range is malformed.' }
      $Values = [uint32[]]::new([int]$Field)
      for ($Index = 0; $Index -lt $Values.Length; $Index++) { $Values[$Index] = [BitConverter]::ToUInt32($Bytes, $Offset + 5 + ($Index * 4)) }
      return [pscustomobject][ordered]@{ Type = $Type; Value = $Values; Offset = $Offset; NextOffset = [int]($Offset + 6 + (4 * $Field)) }
    }
    default { throw "Unsupported AKInstaller table value type $Type." }
  }
}

function Read-AKInstallerProjectTable {
  <#
  .SYNOPSIS
    Decode native AKInstaller project fields, installed-file rows, and registry rows.
  .PARAMETER Bytes
    Decompressed A01 archive entry.
  .PARAMETER TableProfile
    Table string transform selected from the validated native footer marker.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ValidateSet('ModernRc4', 'LegacyXor')][string]$TableProfile = 'ModernRc4'
  )

  if ($Bytes.Length -lt 20 -or $Bytes.Length -gt $Script:AKInstallerMaximumTableBytes -or
    [Text.Encoding]::ASCII.GetString($Bytes, 0, 15) -cne 'STPSETUPVERSION') {
    throw 'The AKInstaller A01 table header is invalid.'
  }
  $Text = [Text.Encoding]::Latin1.GetString($Bytes)
  $Records = [ordered]@{}
  $MalformedRecords = [Collections.Generic.List[object]]::new()
  $DuplicateRecords = [Collections.Generic.List[object]]::new()
  $ConsumedRanges = [Collections.Generic.List[object]]::new()
  foreach ($Match in [regex]::Matches($Text, 'STP[A-Za-z0-9]{4,40}')) {
    # A01 interleaves typed records with fixed-layout tables, so there is no
    # single sequential cursor. Reject marker-like strings inside a previously
    # validated record while retaining independent records after raw sections.
    if ($ConsumedRanges | Where-Object { $Match.Index -ge $_.Start -and $Match.Index -lt $_.End }) { continue }
    $CellOffset = $Match.Index + $Match.Length
    if ($CellOffset -ge $Bytes.Length -or $Bytes[$CellOffset] -notin 1, 2, 3, 4, 5, 6) { continue }
    try {
      $Cell = Read-AKInstallerTableCell -Bytes $Bytes -Offset $CellOffset -TableProfile $TableProfile
    } catch {
      $MalformedRecords.Add([pscustomobject][ordered]@{ Name = $Match.Value; Offset = $Match.Index; Error = $_.Exception.Message })
      continue
    }
    if ($Records.Contains($Match.Value)) {
      $DuplicateRecords.Add([pscustomobject][ordered]@{ Name = $Match.Value; FirstOffset = $Records[$Match.Value].Offset; DuplicateOffset = $Match.Index })
      continue
    }
    $Records[$Match.Value] = [pscustomobject][ordered]@{ Name = $Match.Value; Value = $Cell.Value; Type = $Cell.Type; Offset = $Match.Index; NextOffset = $Cell.NextOffset }
    $ConsumedRanges.Add([pscustomobject]@{ Start = $Match.Index; End = $Cell.NextOffset })
  }

  # Current rows have four typed strings followed by an uncompressed-size
  # dword. Classic rows omit the condition cell, but still store that dword
  # immediately after file name, member key, and destination. Do not infer the
  # row profile from the size's low byte because values 1..6 are valid sizes
  # and are also the type tags used by modern cells.
  $Files = [Collections.Generic.List[object]]::new()
  foreach ($Match in [regex]::Matches($Text, 'STPL(?<Class>[BC])(?<Index>\d+)BBBB')) {
    $Cursor = $Match.Index + $Match.Length
    $Cells = [Collections.Generic.List[object]]::new()
    try {
      for ($CellIndex = 0; $CellIndex -lt 3; $CellIndex++) {
        $Cell = Read-AKInstallerTableCell -Bytes $Bytes -Offset $Cursor -TableProfile $TableProfile
        $Cells.Add($Cell.Value)
        $Cursor = $Cell.NextOffset
      }
      $Condition = $null
      $UnpackedSize = 0u
      if ($TableProfile -ceq 'LegacyXor') {
        if ($Cursor + 4 -gt $Bytes.Length) { throw 'The AKInstaller classic file row size is truncated.' }
        $UnpackedSize = [uint32][BitConverter]::ToUInt32($Bytes, $Cursor)
        $Cursor += 4
      } elseif ($Cursor -lt $Bytes.Length -and $Bytes[$Cursor] -in 1, 2, 3, 4, 5, 6) {
        $Cell = Read-AKInstallerTableCell -Bytes $Bytes -Offset $Cursor -TableProfile $TableProfile
        $Condition = [string]$Cell.Value
        $Cursor = $Cell.NextOffset
        if ($Cursor + 4 -gt $Bytes.Length) { throw 'The AKInstaller file row size is truncated.' }
        $UnpackedSize = [uint32][BitConverter]::ToUInt32($Bytes, $Cursor)
        $Cursor += 4
      } else {
        throw 'The AKInstaller file row condition field is malformed.'
      }
      $Files.Add([pscustomobject][ordered]@{
          Class          = $Match.Groups['Class'].Value -eq 'C' ? 'Installed' : 'Temporary'
          Index          = [int]$Match.Groups['Index'].Value
          FileName       = [string]$Cells[0]
          ArchiveKey     = [string]$Cells[1]
          Destination    = [string]$Cells[2]
          Condition      = $Condition
          UnpackedSize   = $UnpackedSize
          DescriptorName = $Match.Value
        })
    } catch {
      $MalformedRecords.Add([pscustomobject][ordered]@{ Name = $Match.Value; Offset = $Match.Index; Error = $_.Exception.Message })
      continue
    }
  }

  $RegistryRows = [Collections.Generic.List[object]]::new()
  $RegistryIndexes = @($Records.Keys | ForEach-Object {
      $RecordMatch = [regex]::Match($_, '^STPLD(?<Index>\d+)C01C$')
      if ($RecordMatch.Success) { [int]$RecordMatch.Groups['Index'].Value }
    } | Sort-Object -Unique)
  foreach ($Index in $RegistryIndexes) {
    $Fields = [ordered]@{}
    foreach ($Key in $Records.Keys) {
      $FieldMatch = [regex]::Match($Key, "^STPLD${Index}C(?<Field>\d+)C$")
      if ($FieldMatch.Success) { $Fields[$FieldMatch.Groups['Field'].Value] = $Records[$Key].Value }
    }
    $Flags = $Fields['04'] -is [byte[]] ? [byte[]]$Fields['04'] : [byte[]]::new(0)
    $RegistryRows.Add([pscustomobject][ordered]@{
        Index             = $Index
        Path              = [string]$Fields['01']
        Value             = $Fields['02']
        TypeCode          = $Flags.Length -gt 0 ? [int]$Flags[0] : $null
        Create            = $Flags.Length -gt 1 ? [bool]$Flags[1] : $null
        RemoveOnUninstall = $Flags.Length -gt 2 ? [bool]$Flags[2] : $null
        OnlyIfNotExists   = $Flags.Length -gt 3 ? [bool]$Flags[3] : $null
        IgnoreErrors      = $Flags.Length -gt 4 ? [bool]$Flags[4] : $null
        NoTrailingSlash   = $Flags.Length -gt 5 ? [bool]$Flags[5] : $null
        Flags             = $Flags
        ConditionValue    = $Fields['06']
        Fields            = [pscustomobject]$Fields
      })
  }

  return [pscustomobject][ordered]@{
    FormatVersion    = [int]$Bytes[15]
    EngineVersion    = [uint32][BitConverter]::ToUInt32($Bytes, 16)
    StringProfile    = $TableProfile
    Records          = $Records
    Files            = @($Files | Sort-Object Class, Index)
    RegistryRows     = @($RegistryRows)
    MalformedRecords = @($MalformedRecords)
    DuplicateRecords = @($DuplicateRecords)
  }
}

function Get-AKInstallerIndexedRecordGroup {
  <#
  .SYNOPSIS
    Group source-backed indexed A01 record families without assigning unknown fields.
  .PARAMETER Table
    Decoded native project table.
  .PARAMETER Prefix
    Literal record prefix ending immediately before the decimal row index.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)]$Table, [Parameter(Mandatory)][string]$Prefix)

  $Rows = [ordered]@{}
  foreach ($Name in $Table.Records.Keys) {
    $Match = [regex]::Match($Name, "^$([regex]::Escape($Prefix))(?<Index>\d+)(?<Field>.*)$")
    if (-not $Match.Success) { continue }
    $Index = [int]$Match.Groups['Index'].Value
    $IndexKey = [string]$Index
    if (-not $Rows.Contains($IndexKey)) { $Rows[$IndexKey] = [ordered]@{} }
    $Field = $Match.Groups['Field'].Value
    $Rows[$IndexKey][$Field] = $Table.Records[$Name].Value
  }
  foreach ($IndexKey in @($Rows.Keys | Sort-Object { [int]$_ })) {
    [pscustomobject][ordered]@{ Index = [int]$IndexKey; Fields = $Rows[$IndexKey] }
  }
}

function ConvertFrom-AKInstallerFileOperation {
  <#
  .SYNOPSIS
    Decode one compact native AKInstaller file-operation record.
  .PARAMETER Value
    Compiled operation string. The first three UTF-16 characters select applicability, operation, and execution phase; the remaining pipe-delimited fields contain source, destination, and condition values.
  .PARAMETER Variables
    Deterministic compiled-variable values used only for literal path projection.
  .PARAMETER Index
    Zero-based source-table row index retained for evidence correlation.
  .PARAMETER RawFields
    Original grouped table fields retained for unknown future format values.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
    [Parameter(Mandatory)][Collections.IDictionary]$Variables,
    [int]$Index = -1,
    [AllowNull()]$RawFields
  )

  # The operation and phase codes are established independently by the builder's
  # UI serializer and the native runtime dispatcher. Unknown values stay raw.
  $ApplicabilityNames = [ordered]@{ '0' = 'SetupAndUpdate'; '1' = 'SetupOnly'; '2' = 'UpdateOnly' }
  $OperationNames = [ordered]@{
    'D' = 'DeleteFile'; 'R' = 'Rename'; 'C' = 'CopyFile'; 'M' = 'MakeDir'; '-' = 'DeleteWildCard'
    '+' = 'CopyWildCard'; '!' = 'RemoveDirIfEmpty'; 'F' = 'MoveFile'; 'X' = 'CopyMultiWildCard'
  }
  $PhaseNames = [ordered]@{
    'V' = 'BeforeInstallation'; 'N' = 'AfterInstallation'; 'R' = 'Rollback'
    'U' = 'BeforeUninstallation'; 'X' = 'AfterUninstallation'
  }

  $HasHeader = $Value.Length -ge 3
  $ApplicabilityCode = $HasHeader ? [string]$Value[0] : $null
  $OperationCode = $HasHeader ? [string]$Value[1] : $null
  $PhaseCode = $HasHeader ? [string]$Value[2] : $null
  $Fields = $HasHeader ? $Value.Substring(3).Split([char]'|', 3, [StringSplitOptions]::None) : [string[]]@()
  $Source = $Fields.Length -gt 0 ? (Resolve-AKInstallerVariable -Value $Fields[0] -Variables $Variables) : $null
  $Destination = $Fields.Length -gt 1 ? (Resolve-AKInstallerVariable -Value $Fields[1] -Variables $Variables) : $null
  $Condition = $Fields.Length -gt 2 ? $Fields[2] : $null
  $RequiresDestination = $OperationCode -in 'R', 'C', 'F', '+', 'X'
  $IsStructurallyValid = $HasHeader -and -not [string]::IsNullOrWhiteSpace($Source) -and (-not $RequiresDestination -or -not [string]::IsNullOrWhiteSpace($Destination))

  [pscustomobject][ordered]@{
    Index = $Index; EncodedOperation = $Value
    ApplicabilityCode = $ApplicabilityCode; Applicability = $ApplicabilityNames[$ApplicabilityCode]
    OperationCode = $OperationCode; Operation = $OperationNames[$OperationCode]
    PhaseCode = $PhaseCode; Phase = $PhaseNames[$PhaseCode]
    Source = $Source; Destination = $Destination; Condition = $Condition
    IsDecoded = $HasHeader -and $ApplicabilityNames.Contains($ApplicabilityCode) -and $OperationNames.Contains($OperationCode) -and $PhaseNames.Contains($PhaseCode)
    IsStructurallyValid = $IsStructurallyValid; RawFields = $RawFields
  }
}

function Get-AKInstallerNativeSystemEffectInfo {
  <#
  .SYNOPSIS
    Project native shortcut, INI, execution, condition, permission, property, extension, directory-attribute, and file-operation records.
  .PARAMETER Table
    Decoded native project table.
  .PARAMETER Variables
    Deterministic compiled-variable values used only for literal path projection.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$Table, [Parameter(Mandatory)][Collections.IDictionary]$Variables)

  $Shortcuts = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLF')) {
    [pscustomobject][ordered]@{
      Index = $Row.Index; Name = $Row.Fields.E01E; Directory = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.E02E) -Variables $Variables; Arguments = $Row.Fields.E03E
      WorkingDirectory = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.E04E) -Variables $Variables; Description = $Row.Fields.E05E; Target = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.E06E) -Variables $Variables
      Icon = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.E07E) -Variables $Variables; HotKey = $Row.Fields.E08E; Condition = $Row.Fields.A06C; RawFields = $Row.Fields
    }
  }
  $IniFileOperations = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLG')) {
    [pscustomobject][ordered]@{
      Index = $Row.Index; Path = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.F01F) -Variables $Variables; Section = $Row.Fields.F02F; Key = $Row.Fields.F03F
      Value = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.F04F) -Variables $Variables; Flags = $Row.Fields.F05F; Condition = $Row.Fields.A06C; RawFields = $Row.Fields
    }
  }
  $ExecutedPayloads = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLI')) {
    [pscustomobject][ordered]@{
      Index = $Row.Index; Path = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.G01G) -Variables $Variables; Arguments = $Row.Fields.G02G; WorkingDirectory = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.G03G) -Variables $Variables
      DisplayName = $Row.Fields.G23G; SuccessCodes = $Row.Fields.G28G; DetectionProperty = $Row.Fields.G31G
      Condition = $Row.Fields.AX5B; DetectionExpression = $Row.Fields.AX5C; RawFields = $Row.Fields
    }
  }
  $LaunchConditions = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLV')) {
    [pscustomobject][ordered]@{
      Index = $Row.Index; Condition = $Row.Fields.A06C; Message = $Row.Fields.H05H
      AbortOnFailure = $null -ne $Row.Fields.H06H ? [bool][int]$Row.Fields.H06H : $null; RawFields = $Row.Fields
    }
  }
  $Permissions = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLX')) {
    [pscustomobject][ordered]@{
      Index = $Row.Index; Path = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.B24A) -Variables $Variables; Principal = $Row.Fields.B24B; Domain = $Row.Fields.B24C
      AccessMask = $Row.Fields.B24D; Flags = $Row.Fields.B24E; RawFields = $Row.Fields
    }
  }
  $DirectoryAttributeOperations = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLS')) {
    $AttributeMask = $null -ne $Row.Fields.B09B ? [uint32]$Row.Fields.B09B : $null
    [pscustomobject][ordered]@{
      Index = $Row.Index; Path = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.B01B) -Variables $Variables
      AttributeMask = $AttributeMask; Attributes = $null -ne $AttributeMask ? ([IO.FileAttributes]$AttributeMask).ToString() : $null; RawFields = $Row.Fields
    }
  }
  $CompiledProperties = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLW')) {
    [pscustomobject][ordered]@{
      Index = $Row.Index; Name = $Row.Fields.I01H; Value = Resolve-AKInstallerVariable -Value ([string]$Row.Fields.I02H) -Variables $Variables
      TypeCode = $Row.Fields.I03H; Condition = $Row.Fields.A06C; RawFields = $Row.Fields
    }
  }
  $ExtensionModules = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPEX')) {
    [pscustomobject][ordered]@{
      Index = $Row.Index; Identifier = $Row.Fields.EXA0; LibraryArchiveKey = $Row.Fields.EXA1
      DataArchiveKey = $Row.Fields.EXA2; DisplayText = $Row.Fields.EXA3; RawFields = $Row.Fields
    }
  }
  $FileOperations = foreach ($Row in @(Get-AKInstallerIndexedRecordGroup -Table $Table -Prefix 'STPLKNXN')) {
    ConvertFrom-AKInstallerFileOperation -Value ([string]$Row.Fields.'') -Variables $Variables -Index $Row.Index -RawFields $Row.Fields
  }
  [pscustomobject][ordered]@{
    Shortcuts = @($Shortcuts); IniFileOperations = @($IniFileOperations); ExecutedPayloads = @($ExecutedPayloads)
    LaunchConditions = @($LaunchConditions); Permissions = @($Permissions); DirectoryAttributeOperations = @($DirectoryAttributeOperations)
    CompiledProperties = @($CompiledProperties); ExtensionModules = @($ExtensionModules); FileOperations = @($FileOperations)
  }
}

function Get-AKInstallerNativeArpInfo {
  <#
  .SYNOPSIS
    Reconstruct visible and hidden native Apps & Features entries from explicit registry writes.
  .PARAMETER RegistryWrite
    Resolved compiled registry writes.
  .PARAMETER CompiledProductCode
    Project identity used only to select the primary entry when multiple keys exist.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryWrite, [AllowNull()][string]$CompiledProductCode)

  $Groups = [ordered]@{}
  foreach ($Write in $RegistryWrite) {
    if ($Write.Create -eq $false -or $Write.Key -notmatch '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)(?<Code>[^\\]+)$') { continue }
    $Identity = "$($Write.Root)|$($Write.View)|$($Write.Key)"
    if (-not $Groups.Contains($Identity)) {
      $Groups[$Identity] = [ordered]@{ ProductCode = $Matches.Code; Root = $Write.Root; View = $Write.View; Key = $Write.Key; Values = [ordered]@{}; Writes = [Collections.Generic.List[object]]::new() }
    }
    $Groups[$Identity].Values[[string]$Write.Name] = $Write.Value
    $Groups[$Identity].Writes.Add($Write)
  }

  $Entries = [Collections.Generic.List[object]]::new()
  foreach ($Group in $Groups.Values) {
    $Values = $Group.Values
    $SystemComponent = 0
    $HasSystemComponent = $Values.Contains('SystemComponent')
    if ($HasSystemComponent -and -not [int]::TryParse([string]$Values.SystemComponent, [ref]$SystemComponent)) { $SystemComponent = 1 }
    $DisplayName = [string]$Values.DisplayName
    $IsVisible = -not [string]::IsNullOrWhiteSpace($DisplayName) -and $SystemComponent -eq 0
    $Scope = $Group.Root -eq 'HKLM' ? 'machine' : ($Group.Root -eq 'HKCU' ? 'user' : $null)
    $ManifestEntry = [ordered]@{ ProductCode = $Group.ProductCode; InstallerType = 'exe' }
    foreach ($Name in 'DisplayName', 'DisplayVersion', 'Publisher') {
      if (-not [string]::IsNullOrWhiteSpace([string]$Values[$Name])) { $ManifestEntry[$Name] = [string]$Values[$Name] }
    }
    $Entries.Add([pscustomobject][ordered]@{
        ProductCode = $Group.ProductCode; Root = $Group.Root; View = $Group.View; Key = $Group.Key; Scope = $Scope
        IsVisible = $IsVisible; SystemComponent = $HasSystemComponent ? $SystemComponent : 0; Values = [pscustomobject]$Values
        UninstallString = $Values.UninstallString; QuietUninstallString = $Values.QuietUninstallString; DisplayIcon = $Values.DisplayIcon
        InstallLocation = $Values.InstallLocation; ManifestEntry = [pscustomobject]$ManifestEntry; Writes = @($Group.Writes)
      })
  }
  $VisibleEntries = @($Entries | Where-Object IsVisible)
  $Primary = $VisibleEntries | Where-Object ProductCode -CEQ $CompiledProductCode | Select-Object -First 1
  if (-not $Primary -and $VisibleEntries.Count -eq 1) { $Primary = $VisibleEntries[0] }
  [pscustomobject][ordered]@{
    Entries = @($Entries); VisibleEntries = $VisibleEntries; HiddenEntries = @($Entries | Where-Object { -not $_.IsVisible })
    PrimaryEntry = $Primary; AppsAndFeaturesEntries = @($VisibleEntries.ManifestEntry)
  }
}

function Get-AKInstallerRecordValue {
  param ([Parameter(Mandatory)]$Table, [Parameter(Mandatory)][string]$Name)
  return $Table.Records.Contains($Name) ? $Table.Records[$Name].Value : $null
}

function Resolve-AKInstallerVariable {
  <#
  .SYNOPSIS
    Resolve deterministic native AKInstaller project variables.
  .PARAMETER Value
    Compiled table value containing angle-bracket variables.
  .PARAMETER Variables
    Case-insensitive variable map built from project identity fields.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Value, [Parameter(Mandatory)][Collections.IDictionary]$Variables)

  if ($null -eq $Value) { return $null }
  $null = $Variables.Count
  return [regex]::Replace($Value, '<(?<Name>[A-Za-z0-9_]+)>', {
      param ($Match)
      $Name = $Match.Groups['Name'].Value
      return $Variables.Contains($Name) ? [string]$Variables[$Name] : $Match.Value
    }, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Get-AKInstallerNativeVariableContext {
  <#
  .SYNOPSIS
    Build the deterministic variable map shared by native metadata parsing and extraction.
  .PARAMETER Table
    Decoded native project table containing identity and destination records.
  .PARAMETER Scope
    Optional statically proven installation scope used for shell-folder variables whose values differ between machine and user installations.
  .OUTPUTS
    An object containing the case-insensitive Values dictionary and resolved DefaultInstallLocation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Table,
    [ValidateSet('user', 'machine')][string]$Scope
  )

  # These values are deterministic aliases used by the native runtime. Keep
  # this list shared so extraction never resolves fewer paths than analysis.
  $Variables = [ordered]@{
    PRODUCTNAME    = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA01A')
    REGPRODUCTNAME = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA02A')
    PRODUCTVERSION = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA03A')
    MANUFACTURER   = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA04A')
    PRODUCTCODE    = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAAX4V')
    PROGRAMDIR     = '%ProgramFiles%'
    COMMONFILES    = '%CommonProgramFiles%'
    WINDOWS        = '%WINDIR%'
    SYSTEM         = '%WINDIR%\System32'
    TEMPDIR        = '%TEMP%'
    APPDATA        = '%APPDATA%'
    LOCALAPPDATA   = '%LOCALAPPDATA%'
    COMMONAPPDATA  = '%ProgramData%'
    INSTALLDIR     = $null
  }
  $DefaultInstallLocation = Resolve-AKInstallerVariable -Value ([string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA06A')) -Variables $Variables
  $Variables.INSTALLDIR = $DefaultInstallLocation

  # Shell-folder targets depend on the installation context. Add them only
  # when explicit ARP evidence proves one scope; unresolved scope stays raw.
  if ($Scope -ceq 'machine') {
    $Variables.STARTMENU = '%ProgramData%\Microsoft\Windows\Start Menu\Programs'
    $Variables.STARTUP = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'
    $Variables.DESKTOP = '%PUBLIC%\Desktop'
  } elseif ($Scope -ceq 'user') {
    $Variables.STARTMENU = '%APPDATA%\Microsoft\Windows\Start Menu\Programs'
    $Variables.STARTUP = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'
    $Variables.DESKTOP = '%USERPROFILE%\Desktop'
  }

  return [pscustomobject][ordered]@{ Values = $Variables; DefaultInstallLocation = $DefaultInstallLocation }
}

function Get-AKInstallerNativePayloadCatalog {
  <#
  .SYNOPSIS
    Project native STPLC file rows into safe installed-relative paths.
  .PARAMETER Table
    Decoded native project table.
  .PARAMETER Variables
    Deterministic project-variable map.
  .PARAMETER DefaultInstallLocation
    Resolved installation root used to remove the target prefix.
  .PARAMETER Entry
    Optional physical payload records used to validate declared expanded sizes and to supply extraction lengths.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)]$Table,
    [Parameter(Mandatory)][Collections.IDictionary]$Variables,
    [AllowNull()][string]$DefaultInstallLocation,
    [AllowEmptyCollection()][object[]]$Entry = @()
  )

  $EntriesByKey = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  foreach ($PhysicalEntry in $Entry) {
    if (-not $EntriesByKey.ContainsKey([string]$PhysicalEntry.Key)) { $EntriesByKey.Add([string]$PhysicalEntry.Key, $PhysicalEntry) }
  }
  foreach ($File in @($Table.Files | Where-Object Class -CEQ 'Installed')) {
    $TargetDirectory = Resolve-AKInstallerVariable -Value $File.Destination -Variables $Variables
    $Combined = "$($TargetDirectory.TrimEnd('\'))\$($File.FileName)"
    if (-not [string]::IsNullOrWhiteSpace($DefaultInstallLocation) -and $Combined.StartsWith($DefaultInstallLocation, [StringComparison]::OrdinalIgnoreCase)) {
      $Path = $Combined.Substring($DefaultInstallLocation.Length).TrimStart('\')
    } else {
      $Path = Join-Path '_destinations' (($Combined -replace '[:<>"|?*]', '_').TrimStart('\'))
    }
    $PhysicalEntry = $null
    $HasPhysicalEntry = $EntriesByKey.TryGetValue([string]$File.ArchiveKey, [ref]$PhysicalEntry)
    $DeclaredLength = [long]$File.UnpackedSize
    $PhysicalLength = $HasPhysicalEntry ? [long]$PhysicalEntry.Length : $null
    $Length = $HasPhysicalEntry ? $PhysicalLength : $DeclaredLength
    $SizeMatchesPhysical = $HasPhysicalEntry -and $DeclaredLength -gt 0 ? $DeclaredLength -eq $PhysicalLength : $null
    [pscustomobject][ordered]@{
      Path = $Path; FileName = $File.FileName; ArchiveKey = $File.ArchiveKey; Destination = $File.Destination; Condition = $File.Condition
      Length = $Length; DeclaredLength = $DeclaredLength; PhysicalLength = $PhysicalLength; SizeMatchesPhysical = $SizeMatchesPhysical
    }
  }
}

function ConvertTo-AKInstallerClassicEntryKey {
  <#
  .SYNOPSIS
    Convert one classic catalog identifier to the key stored in project file rows.
  .PARAMETER Identifier
    Identifier bytes from a classic member descriptor.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][byte[]]$Identifier)

  $Hex = [Convert]::ToHexString($Identifier)
  if ($Identifier.Length -ne 4 -or $Identifier[0] -ne 0xD1 -or ($Identifier[1] -band 0xF0) -ne 0xA0) { return "ID-$Hex" }
  $Prefix = 'A' + ($Identifier[1] -band 0x0F).ToString('X1')
  if ($Identifier[2] -ge 0xF1 -and $Identifier[2] -le 0xFA) { return $Prefix + [char]([int][char]'a' + $Identifier[2] - 0xF1) }
  if (($Identifier[2] -band 0xF0) -eq 0xA0) { return $Prefix + ($Identifier[2] -band 0x0F).ToString('X1') }
  return "ID-$Hex"
}

function Read-AKInstallerClassicEntry {
  <#
  .SYNOPSIS
    Expand one bounded classic GZip member into memory.
  .PARAMETER Path
    Resolved installer path that owns the member.
  .PARAMETER Entry
    Validated classic catalog record with absolute offset and compressed size.
  .PARAMETER MaximumBytes
    Maximum accepted uncompressed size.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Entry,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  if ([long]$Entry.Length -gt $MaximumBytes) { throw "The AKInstaller classic member exceeds the $MaximumBytes-byte output limit." }
  $Source = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
  $Range = $null
  $Output = [IO.MemoryStream]::new([int][Math]::Min([long]$Entry.Length, [int]::MaxValue))
  try {
    $Range = New-BoundedReadStream -Stream $Source -Offset $Entry.Offset -Length $Entry.CompressedSize -LeaveOpen
    $null = Expand-InstallerCompressedStream -Algorithm GZip -Stream $Range -Destination $Output -MaximumBytes $MaximumBytes -CompressedSize $Entry.CompressedSize -UncompressedSize $Entry.Length
    return , $Output.ToArray()
  } finally {
    if ($Range) { $Range.Dispose() }
    $Output.Dispose()
    $Source.Dispose()
  }
}

function Get-AKInstallerClassicNativeContext {
  <#
  .SYNOPSIS
    Validate the classic native GZip overlay and recover its compiled project table.
  .PARAMETER File
    Resolved installer file.
  .PARAMETER MarkerOffset
    Absolute offset of the final KAPI marker.
  .PARAMETER FooterFields
    Six uint32 fields immediately before the marker.
  .PARAMETER Layout
    Parsed PE layout used to prove the overlay boundary.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][long]$MarkerOffset,
    [Parameter(Mandatory)][uint32[]]$FooterFields,
    [Parameter(Mandatory)]$Layout
  )

  if ($FooterFields.Count -ne 6) { return $null }
  $ImageEnd = [long](($Layout.Sections | ForEach-Object { [long]$_.RawOffset + [long]$_.RawSize } | Measure-Object -Maximum).Maximum)
  $PayloadOffset = [long]$FooterFields[4]
  $FooterOffset = $MarkerOffset - 24L
  if ($FooterFields[1] -ne $ImageEnd -or [long]$FooterFields[1] + [long]$FooterFields[2] -ne $PayloadOffset -or $PayloadOffset -lt $ImageEnd -or $FooterOffset -le $PayloadOffset) { return $null }

  $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
  try {
    # Classic catalogs have no pointer in the footer. Locate the only candidate
    # whose count, variable-width descriptors, and compressed sizes consume the
    # complete range between the GZip payload and the six-word footer.
    $MaximumCatalogBytes = [Math]::Min($FooterOffset - $PayloadOffset, 4L + (11L * $Script:AKInstallerMaximumEntries))
    $CatalogSearchOffset = $FooterOffset - $MaximumCatalogBytes
    $CatalogBytes = Read-BinaryBytes -Stream $Stream -Offset $CatalogSearchOffset -Count ([int]$MaximumCatalogBytes)
    $Candidates = [Collections.Generic.List[object]]::new()
    for ($CandidateIndex = 0; $CandidateIndex -le $CatalogBytes.Length - 4; $CandidateIndex++) {
      $Count = [long][BitConverter]::ToUInt32($CatalogBytes, $CandidateIndex)
      $Remaining = $CatalogBytes.Length - $CandidateIndex
      if ($Count -le 0 -or $Count -gt $Script:AKInstallerMaximumEntries -or $Remaining -lt 4L + (9L * $Count) -or $Remaining -gt 4L + (11L * $Count)) { continue }
      $Descriptors = [Collections.Generic.List[object]]::new([int]$Count)
      $DescriptorCursor = $CandidateIndex + 4
      $CompressedTotal = 0L
      for ($Index = 0; $Index -lt $Count; $Index++) {
        if ($DescriptorCursor -ge $CatalogBytes.Length) { $Descriptors.Clear(); break }
        $Kind = [int]$CatalogBytes[$DescriptorCursor++]
        $IdentifierLength = switch ($Kind) { 4 { 4 }; 6 { 6 }; default { 0 } }
        if ($IdentifierLength -eq 0 -or $DescriptorCursor + $IdentifierLength + 4 -gt $CatalogBytes.Length) { $Descriptors.Clear(); break }
        $Identifier = [byte[]]$CatalogBytes[$DescriptorCursor..($DescriptorCursor + $IdentifierLength - 1)]
        $DescriptorCursor += $IdentifierLength
        $CompressedSize = [long][BitConverter]::ToUInt32($CatalogBytes, $DescriptorCursor)
        $DescriptorCursor += 4
        if ($CompressedSize -lt 18) { $Descriptors.Clear(); break }
        $CompressedTotal += $CompressedSize
        $Descriptors.Add([pscustomobject]@{ Kind = $Kind; Identifier = $Identifier; CompressedSize = $CompressedSize })
      }
      if ($Descriptors.Count -eq $Count -and $DescriptorCursor -eq $CatalogBytes.Length -and $PayloadOffset + $CompressedTotal -eq $CatalogSearchOffset + $CandidateIndex) {
        $Candidates.Add([pscustomobject]@{ Offset = $CatalogSearchOffset + $CandidateIndex; Descriptors = @($Descriptors) })
      }
    }
    if ($Candidates.Count -ne 1) { return $null }
    $CatalogOffset = [long]$Candidates[0].Offset
    $Descriptors = @($Candidates[0].Descriptors)
    $Entries = [Collections.Generic.List[object]]::new($Descriptors.Count)
    $Cursor = $PayloadOffset
    for ($Index = 0; $Index -lt $Descriptors.Count; $Index++) {
      $Descriptor = $Descriptors[$Index]
      $CompressedSize = [long]$Descriptor.CompressedSize
      if ($Cursor + $CompressedSize -gt $CatalogOffset) { return $null }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $Cursor -Count 3
      if ($Header[0] -ne 0x1F -or $Header[1] -ne 0x8B -or $Header[2] -ne 8) { return $null }
      $Trailer = Read-BinaryBytes -Stream $Stream -Offset ($Cursor + $CompressedSize - 8) -Count 8
      $ExpandedSize = [long][BitConverter]::ToUInt32($Trailer, 4)
      if ($ExpandedSize -gt $Script:AKInstallerMaximumExpandedBytes) { throw 'An AKInstaller classic member exceeds the expanded-size limit.' }
      $Entries.Add([pscustomobject][ordered]@{
          Key = ConvertTo-AKInstallerClassicEntryKey -Identifier $Descriptor.Identifier; Identifier = [Convert]::ToHexString($Descriptor.Identifier); Kind = $Descriptor.Kind; Index = $Index + 1
          Offset = $Cursor; CompressedSize = $CompressedSize; Length = $ExpandedSize; Compression = 'GZip'
        })
      $Cursor += $CompressedSize
    }
    if ($Cursor -ne $CatalogOffset) { return $null }
  } finally { $Stream.Dispose() }

  $ProjectTable = $null
  foreach ($Entry in $Entries) {
    if ($Entry.Length -lt 20 -or $Entry.Length -gt $Script:AKInstallerMaximumTableBytes) { continue }
    $Bytes = Read-AKInstallerClassicEntry -Path $File.FullName -Entry $Entry -MaximumBytes $Script:AKInstallerMaximumTableBytes
    if ([Text.Encoding]::ASCII.GetString($Bytes, 0, [Math]::Min(15, $Bytes.Length)) -cne 'STPSETUPVERSION') { continue }
    $ProjectTable = Read-AKInstallerProjectTable -Bytes $Bytes -TableProfile LegacyXor
    break
  }
  if (-not $ProjectTable -or [string]::IsNullOrWhiteSpace([string](Get-AKInstallerRecordValue -Table $ProjectTable -Name 'STPLAA01A'))) { return $null }
  return [pscustomobject][ordered]@{
    Route = 'AKInstaller/NativeClassicGZip'; TableProfile = 'LegacyXor'; ProjectTable = $ProjectTable; File = $File; MarkerOffset = $MarkerOffset
    ArchiveOffset = $PayloadOffset; ArchiveLength = $CatalogOffset - $PayloadOffset; ArchiveContext = $null; Entries = @($Entries); Password = $null
    FooterFields = $FooterFields; ProtectedConfigurationLength = 0; CatalogOffset = $CatalogOffset
  }
}

function Open-AKInstallerMsiLegacyArchive {
  <#
  .SYNOPSIS
    Open an AKInstallerMSI ZIP whose central-directory signatures use the historical AKI marker.
  .PARAMETER Path
    Resolved bootstrapper path.
  .PARAMETER ArchiveEnd
    Absolute end of the ZIP data immediately before the protected footer strings.
  .PARAMETER Password
    Recovered private ZipCrypto password. It is never returned by the public parser.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'SharpCompress requires the binary-recovered archive password as a string; the parser does not expose or log it.')]
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidateRange(22, [long]::MaxValue)][long]$ArchiveEnd,
    [AllowNull()][string]$Password
  )

  $Stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
  $TemporaryDirectory = $null
  try {
    # ZIP comments are UInt16-sized. Select only an EOCD ending exactly at the
    # protected footer strings so marker-like payload bytes cannot become a route.
    $EocdOffset = @(Find-BinaryPattern -Path $Path -Pattern $Script:AKInstallerZipEocdMarker -Reverse -Maximum 512 | Where-Object {
        if ($_ + 22 -gt $ArchiveEnd) { return $false }
        $Header = Read-BinaryBytes -Stream $Stream -Offset $_ -Count 22
        $_ + 22 + [BitConverter]::ToUInt16($Header, 20) -eq $ArchiveEnd
      } | Select-Object -First 1)
    if ($EocdOffset.Count -eq 0) { return $null }
    $Eocd = Read-BinaryBytes -Stream $Stream -Offset $EocdOffset[0] -Count 22
    if ([BitConverter]::ToUInt16($Eocd, 4) -ne 0 -or [BitConverter]::ToUInt16($Eocd, 6) -ne 0) { throw 'Spanned AKInstallerMSI ZIP media is unsupported.' }
    $EntryCount = [int][BitConverter]::ToUInt16($Eocd, 10)
    if ($EntryCount -le 0 -or $EntryCount -gt $Script:AKInstallerMaximumEntries -or [BitConverter]::ToUInt16($Eocd, 8) -ne $EntryCount) { throw 'The AKInstallerMSI ZIP entry count is invalid.' }
    $CentralSize = [long][BitConverter]::ToUInt32($Eocd, 12)
    $CentralOffset = [long][BitConverter]::ToUInt32($Eocd, 16)
    $ArchiveOffset = [long]$EocdOffset[0] - $CentralSize - $CentralOffset
    $ArchiveLength = $ArchiveEnd - $ArchiveOffset
    if ($ArchiveOffset -lt 0 -or $ArchiveLength -le 0 -or $ArchiveLength -gt $Script:AKInstallerMaximumExpandedBytes) { throw 'The AKInstallerMSI historical ZIP range is invalid.' }
    $CentralStart = $ArchiveOffset + $CentralOffset
    if ($CentralStart -lt $ArchiveOffset -or $CentralStart + $CentralSize -ne $EocdOffset[0]) { throw 'The AKInstallerMSI historical central-directory range is inconsistent.' }
    $Signature = Read-BinaryBytes -Stream $Stream -Offset $CentralStart -Count 4
    if (-not [Linq.Enumerable]::SequenceEqual($Signature, $Script:AKInstallerLegacyCentralMarker)) { return $null }

    $TemporaryDirectory = New-TempFolder
    $ArchivePath = Join-Path $TemporaryDirectory 'payload.zip'
    $null = Export-InstallerArchiveRange -Path $Path -Offset $ArchiveOffset -Length $ArchiveLength -DestinationPath $ArchivePath -CollisionAction Overwrite
    $ArchiveStream = [IO.File]::Open($ArchivePath, 'Open', 'ReadWrite', 'None')
    try {
      $Cursor = $CentralOffset
      for ($Index = 0; $Index -lt $EntryCount; $Index++) {
        if ($Cursor + 46 -gt $CentralOffset + $CentralSize) { throw 'The AKInstallerMSI historical central-directory record is truncated.' }
        $Header = Read-BinaryBytes -Stream $ArchiveStream -Offset $Cursor -Count 46
        if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$Header[0..3], $Script:AKInstallerLegacyCentralMarker)) { throw 'The AKInstallerMSI historical central-directory signature is invalid.' }
        $ArchiveStream.Position = $Cursor
        $ArchiveStream.Write([byte[]](0x50, 0x4B, 0x01, 0x02), 0, 4)
        $NameLength = [BitConverter]::ToUInt16($Header, 28)
        $ExtraLength = [BitConverter]::ToUInt16($Header, 30)
        $CommentLength = [BitConverter]::ToUInt16($Header, 32)
        $Cursor += 46L + $NameLength + $ExtraLength + $CommentLength
      }
      if ($Cursor -ne $CentralOffset + $CentralSize) { throw 'The AKInstallerMSI historical central-directory records do not consume the declared range.' }
    } finally { $ArchiveStream.Dispose() }
    $Archive = Get-InstallerArchive -Path $ArchivePath -Password $Password
    return [pscustomobject][ordered]@{ Archive = $Archive; RangeStream = $null; SourceStream = $null; Offset = $ArchiveOffset; Length = $ArchiveLength; TemporaryDirectory = $TemporaryDirectory; HistoricalCentralDirectory = $true }
  } catch {
    if ($TemporaryDirectory) { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    throw
  } finally { $Stream.Dispose() }
}

function Get-AKInstallerArchiveContext {
  <#
  .SYNOPSIS
    Validate one native or MSI-bootstrapper footer and open its bounded archive.
  .PARAMETER Path
    Resolved installer path.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Layout = Get-PELayout -Path $File.FullName -ErrorAction SilentlyContinue
  if (-not $Layout) { throw 'The file is not a valid PE image.' }
  $NativeMatch = @(
    @{ Route = 'AKInstaller/Native'; Marker = $Script:AKInstallerNativeMarker; TableProfile = 'ModernRc4' }
    @{ Route = 'AKInstaller/NativeLegacy'; Marker = $Script:AKInstallerLegacyNativeMarker; TableProfile = 'LegacyXor' }
  ) | ForEach-Object {
    $Offset = @(Find-BinaryPattern -Path $File.FullName -Pattern $_.Marker -Reverse -Maximum 1 | Select-Object -First 1)
    if ($Offset.Count -gt 0) { [pscustomobject]@{ Route = $_.Route; Offset = [long]$Offset[0]; TableProfile = $_.TableProfile } }
  } | Sort-Object Offset -Descending | Select-Object -First 1
  if ($NativeMatch) {
    $MarkerOffset = $NativeMatch.Offset
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      if ($MarkerOffset -lt 28) { throw 'The AKInstaller native footer is truncated.' }
      $Footer = Read-BinaryBytes -Stream $Stream -Offset ($MarkerOffset - 28) -Count 28
      $Fields = [uint32[]]::new(7)
      for ($Index = 0; $Index -lt 7; $Index++) { $Fields[$Index] = [BitConverter]::ToUInt32($Footer, $Index * 4) }
      $ConfigLength = [long]$Fields[0]
      if ($ConfigLength -gt 4096 -or $MarkerOffset - 28 - $ConfigLength -lt 0) {
        if ($NativeMatch.Route -ceq 'AKInstaller/NativeLegacy') {
          $ClassicFooter = Read-BinaryBytes -Stream $Stream -Offset ($MarkerOffset - 24) -Count 24
          $ClassicFields = [uint32[]]::new(6)
          for ($Index = 0; $Index -lt 6; $Index++) { $ClassicFields[$Index] = [BitConverter]::ToUInt32($ClassicFooter, $Index * 4) }
          $ClassicContext = Get-AKInstallerClassicNativeContext -File $File -MarkerOffset $MarkerOffset -FooterFields $ClassicFields -Layout $Layout
          if ($ClassicContext) { return $ClassicContext }
        }
        throw 'The AKInstaller native protected configuration length is invalid.'
      }
      $Protected = Read-BinaryBytes -Stream $Stream -Offset ($MarkerOffset - 28 - $ConfigLength) -Count ([int]$ConfigLength)
      for ($Index = 0; $Index -lt $Protected.Length; $Index++) { $Protected[$Index] = $Protected[$Index] -bxor 0xA9 }
      $Config = [Text.Encoding]::UTF8.GetString($Protected).Split('|')
      $ArchiveOffset = [long]$Fields[2]; $ArchiveLength = [long]$Fields[3]
      if ($ArchiveOffset -lt 0 -or $ArchiveLength -le 0 -or $ArchiveOffset + $ArchiveLength -gt $MarkerOffset - 28 - $ConfigLength) { throw 'The AKInstaller native archive range is invalid.' }
      $Password = $Config.Count -gt 1 ? $Config[1] : $null
    } finally { $Stream.Dispose() }
    $ArchiveContext = Open-InstallerArchiveRange -Path $File.FullName -Offset $ArchiveOffset -Length $ArchiveLength -Password $Password
    try {
      $Entries = @(Get-InstallerArchiveEntry -Archive $ArchiveContext.Archive)
      $A01 = $Entries | Where-Object Key -CEQ 'A01' | Select-Object -First 1
      if (-not $A01 -or -not ($Entries | Where-Object Key -CEQ 'A11')) { throw 'The native AKInstaller archive lacks required A01/A11 records.' }
      $ProjectTable = Read-AKInstallerProjectTable -Bytes (Read-InstallerArchiveEntryBytes -Entry $A01 -MaximumBytes $Script:AKInstallerMaximumTableBytes) -TableProfile $NativeMatch.TableProfile
      $CompiledName = [string](Get-AKInstallerRecordValue -Table $ProjectTable -Name 'STPLAA01A')
      if ([string]::IsNullOrWhiteSpace($CompiledName)) { throw 'The native AKInstaller project table lacks a decoded application identity.' }
      return [pscustomobject][ordered]@{ Route = $NativeMatch.Route; TableProfile = $NativeMatch.TableProfile; ProjectTable = $ProjectTable; File = $File; MarkerOffset = $MarkerOffset; ArchiveOffset = $ArchiveOffset; ArchiveLength = $ArchiveLength; ArchiveContext = $ArchiveContext; Entries = $Entries; Password = $Password; FooterFields = $Fields; ProtectedConfigurationLength = $ConfigLength }
    } catch { Close-InstallerArchiveRange -Context $ArchiveContext; throw }
  }

  $MsiOffsets = @(Find-BinaryPattern -Path $File.FullName -Pattern $Script:AKInstallerMsiMarker -Reverse -Maximum 2)
  if ($MsiOffsets.Count -gt 0) {
    $MarkerOffset = [long]$MsiOffsets[0]
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      if ($MarkerOffset -lt 16) { throw 'The AKInstallerMSI footer is truncated.' }
      $Footer = Read-BinaryBytes -Stream $Stream -Offset ($MarkerOffset - 16) -Count 16
      $Fields = [uint32[]]::new(4)
      for ($Index = 0; $Index -lt 4; $Index++) { $Fields[$Index] = [BitConverter]::ToUInt32($Footer, $Index * 4) }
      $PasswordLength = [int]($Fields[0] -bxor 0x44)
      $SecondaryLength = [int]($Fields[1] -bxor 0xB2)
      $StringsOffset = $MarkerOffset - 16 - $PasswordLength - $SecondaryLength
      if ($PasswordLength -lt 0 -or $PasswordLength -gt 4096 -or $SecondaryLength -lt 0 -or $SecondaryLength -gt 4096 -or $StringsOffset -lt 0) { throw 'The AKInstallerMSI protected string lengths are invalid.' }
      $PasswordBytes = Read-BinaryBytes -Stream $Stream -Offset $StringsOffset -Count $PasswordLength
      for ($Index = 0; $Index -lt $PasswordBytes.Length; $Index++) { $PasswordBytes[$Index] = $PasswordBytes[$Index] -bxor 0x54 }
      $Password = [Text.Encoding]::ASCII.GetString($PasswordBytes).TrimEnd([char]0)
    } finally { $Stream.Dispose() }
    $LegacyArchiveContext = $null
    foreach ($Range in @(Get-EmbeddedZipArchiveRange -Path $File.FullName -MaximumArchives 16 | Sort-Object Offset -Descending)) {
      if ([long]$Range.Offset + [long]$Range.Length -gt $StringsOffset) { continue }
      $ArchiveContext = $null
      try {
        $ArchiveContext = Open-InstallerArchiveRange -Path $File.FullName -Range $Range -Password $Password
        $Entries = @(Get-InstallerArchiveEntry -Archive $ArchiveContext.Archive)
        if (($Entries | Where-Object Key -CEQ 'Config.ini_') -and ($Entries | Where-Object Key -Match '^File\d+.*\.msi_$')) {
          return [pscustomobject][ordered]@{ Route = 'AKInstallerMSI/Bootstrapper'; File = $File; MarkerOffset = $MarkerOffset; ArchiveOffset = [long]$Range.Offset; ArchiveLength = [long]$Range.Length; ArchiveContext = $ArchiveContext; Entries = $Entries; Password = $Password; FooterFields = $Fields }
        }
      } catch { $null = $_.Exception.Message }
      if ($ArchiveContext) { Close-InstallerArchiveRange -Context $ArchiveContext }
    }
    try {
      $LegacyArchiveContext = Open-AKInstallerMsiLegacyArchive -Path $File.FullName -ArchiveEnd $StringsOffset -Password $Password
      if ($LegacyArchiveContext) {
        $Entries = @(Get-InstallerArchiveEntry -Archive $LegacyArchiveContext.Archive)
        if (($Entries | Where-Object Key -CEQ 'Config.ini_') -and ($Entries | Where-Object Key -Match '^File\d+.*\.msi_$')) {
          return [pscustomobject][ordered]@{ Route = 'AKInstallerMSI/BootstrapperLegacy'; File = $File; MarkerOffset = $MarkerOffset; ArchiveOffset = [long]$LegacyArchiveContext.Offset; ArchiveLength = [long]$LegacyArchiveContext.Length; ArchiveContext = $LegacyArchiveContext; Entries = $Entries; Password = $Password; FooterFields = $Fields }
        }
      }
    } catch {
      if ($LegacyArchiveContext) { Close-AKInstallerContext -Context ([pscustomobject]@{ ArchiveContext = $LegacyArchiveContext }) }
      throw
    }
    if ($LegacyArchiveContext) { Close-AKInstallerContext -Context ([pscustomobject]@{ ArchiveContext = $LegacyArchiveContext }) }
    throw 'The AKInstallerMSI marker is present, but no matching encrypted bootstrapper archive was found.'
  }

  return $null
}

function Close-AKInstallerContext {
  param ([AllowNull()]$Context)
  if ($Context -and $Context.ArchiveContext) {
    $TemporaryDirectory = $Context.ArchiveContext.PSObject.Properties['TemporaryDirectory']?.Value
    try { Close-InstallerArchiveRange -Context $Context.ArchiveContext } finally {
      if ($TemporaryDirectory) { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
}

function Get-AKInstallerDirectMsiContext {
  <#
  .SYNOPSIS
    Locate and verify the direct embedded-MSI AKInstallerMSI route.
  .PARAMETER Path
    Resolved PE path.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $Layout = Get-PELayout -Path $Path -ErrorAction SilentlyContinue
  if (-not $Layout) { return $null }
  # The direct-MSI host can place the CFB before the final PE section extent,
  # so search the complete file and let the MSI parser provide the strong
  # AKInstallerMSI CreatingApp check.
  $Offsets = @(Find-BinaryPattern -Path $Path -Pattern $Script:AKInstallerCfbMarker -Maximum 8)
  foreach ($Offset in $Offsets) {
    $LogicalEnd = (Get-Item -LiteralPath $Path).Length
    $Certificate = $Layout.DataDirectories['Certificate']
    if ($Certificate -and $Certificate.Offset -gt $Offset) { $LogicalEnd = [long]$Certificate.Offset }
    if ($LogicalEnd -le $Offset) { continue }
    $TemporaryDirectory = New-TempFolder
    try {
      $MsiPath = Join-Path $TemporaryDirectory 'embedded.msi'
      $null = Export-InstallerArchiveRange -Path $Path -Offset $Offset -Length ($LogicalEnd - $Offset) -DestinationPath $MsiPath -CollisionAction Overwrite
      $Info = Get-MsiInstallerInfo -Path $MsiPath
      if ([string]$Info.SummaryCreatingApplication -notmatch '(?i)\bAKInstallerMSI\b') { continue }
      return [pscustomobject][ordered]@{ Route = 'AKInstallerMSI/EmbeddedMsi'; File = Get-Item -LiteralPath $Path; ArchiveOffset = [long]$Offset; ArchiveLength = [long]($LogicalEnd - $Offset); MsiInfo = $Info }
    } catch { $null = $_.Exception.Message }
    finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
  }
  return $null
}

function Get-AKInstallerLocalizedIniValue {
  param ([Parameter(Mandatory)][Collections.IDictionary]$Section, [Parameter(Mandatory)][string]$Name)
  if ($Section.Contains($Name)) { return $Section[$Name] }
  foreach ($Language in 1033, 1031) { if ($Section.Contains("${Name}_${Language}")) { return $Section["${Name}_${Language}"] } }
  $Key = @($Section.Keys | Where-Object { $_ -match "^$([regex]::Escape($Name))_\d+$" } | Select-Object -First 1)
  return $Key.Count -gt 0 ? $Section[$Key[0]] : $null
}

function Get-AKInstallerMsiLaunchCondition {
  <#
  .SYNOPSIS
    Project indexed AKInstallerMSI launch conditions from Config.ini.
  .PARAMETER Configuration
    Parsed bootstrapper configuration.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Configuration)

  $Section = $Configuration['LaunchCondition']
  if (-not $Section) { return }
  $Indexes = @($Section.Keys | ForEach-Object {
      $Match = [regex]::Match([string]$_, '^Entry(?<Index>\d+)_Condition$')
      if ($Match.Success) { [int]$Match.Groups['Index'].Value }
    } | Sort-Object -Unique)
  foreach ($Index in $Indexes) {
    $Abort = 0
    $HasAbort = [int]::TryParse([string]$Section["Entry${Index}_Abort"], [ref]$Abort)
    [pscustomobject][ordered]@{
      Index = $Index; Condition = [string]$Section["Entry${Index}_Condition"]
      Message = Get-AKInstallerLocalizedIniValue -Section $Section -Name "Entry${Index}_Text"
      AbortOnFailure = $HasAbort ? [bool]$Abort : $null; Type = $Section["Entry${Index}_Typ"]
    }
  }
}

function Get-AKInstallerMsiFilePolicy {
  <#
  .SYNOPSIS
    Preserve indexed prerequisite conditions and detection tests from one FileN section.
  .PARAMETER Section
    Parsed FileN configuration section.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Section)

  $Conditions = @($Section.Keys | ForEach-Object {
      $Match = [regex]::Match([string]$_, '^Condition(?<Index>\d+)$')
      if ($Match.Success) { [pscustomobject][ordered]@{ Index = [int]$Match.Groups['Index'].Value; Expression = [string]$Section[$_] } }
    } | Sort-Object Index)
  $Tests = @($Section.Keys | ForEach-Object {
      $Match = [regex]::Match([string]$_, '^Test(?<Index>\d+)$')
      if ($Match.Success) {
        $Index = [int]$Match.Groups['Index'].Value
        [pscustomobject][ordered]@{
          Index = $Index; Type = $Section[$_]; Path = $Section["Path$Index"]; Compare = $Section["Compare$Index"]
          Version = $Section["Version$Index"]; Value = $Section["Value$Index"]
        }
      }
    } | Sort-Object Index)
  [pscustomobject][ordered]@{
    Conditions = $Conditions; DetectionTests = $Tests; InstallMode = $Section.InstallMode; StartMode = $Section.Start
    RebootPolicy = $Section.Reboot; CancelOnFailure = $Section.Cancel; ReturnCodePolicy = $Section.RetvalStopCodes
  }
}

function Export-AKInstallerEntryMap {
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][object[]]$Catalog,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Rename',
    [long]$MaximumExpandedBytes = $Script:AKInstallerMaximumExpandedBytes,
    [int]$MaximumEntries = $Script:AKInstallerMaximumEntries
  )

  $EntriesByKey = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  foreach ($Entry in $Context.Entries) {
    if (-not $EntriesByKey.ContainsKey([string]$Entry.Key)) { $EntriesByKey.Add([string]$Entry.Key, $Entry) }
  }
  $Selection = [Collections.Generic.List[object]]::new()
  $SelectedBytes = 0L
  foreach ($Item in $Catalog) {
    if (-not (Test-ExtractionPattern -Path $Item.Path -Pattern $Name) -and -not (Test-ExtractionPattern -Path ([IO.Path]::GetFileName($Item.Path)) -Pattern $Name)) { continue }
    if ($Selection.Count + 1 -gt $MaximumEntries) { throw "The AKInstaller selection exceeds the $MaximumEntries-entry limit." }
    $Entry = $null
    if (-not $EntriesByKey.TryGetValue([string]$Item.ArchiveKey, [ref]$Entry)) { throw "AKInstaller archive entry '$($Item.ArchiveKey)' is missing." }
    if ($Entry.Length -lt 0 -or $SelectedBytes + $Entry.Length -gt $MaximumExpandedBytes) { throw "The AKInstaller selection exceeds the $MaximumExpandedBytes-byte output limit." }
    $SelectedBytes += $Entry.Length
    $Selection.Add([pscustomobject]@{ Item = $Item; Entry = $Entry })
  }

  # Perform all structural and size checks before creating output. A malformed
  # later record must not leave a partially extracted selection behind.
  $Files = [Collections.Generic.List[IO.FileInfo]]::new()
  $Reserved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Total = 0L
  foreach ($Selected in $Selection) {
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Selected.Item.Path -CollisionAction $CollisionAction -ReservedPath $Reserved
    if (-not $Target.ShouldWrite) { continue }
    if ($Selected.Entry.PSObject.Properties['Compression'] -and $Selected.Entry.Compression -ceq 'GZip') {
      $Source = [IO.File]::Open($Context.File.FullName, 'Open', 'Read', 'ReadWrite')
      $Range = $null
      $OutputStream = $null
      try {
        $Range = New-BoundedReadStream -Stream $Source -Offset $Selected.Entry.Offset -Length $Selected.Entry.CompressedSize -LeaveOpen
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if (-not [string]::IsNullOrWhiteSpace($Parent)) { $null = [IO.Directory]::CreateDirectory($Parent) }
        $OutputStream = [IO.File]::Create($Target.Path)
        $null = Expand-InstallerCompressedStream -Algorithm GZip -Stream $Range -Destination $OutputStream -MaximumBytes ($MaximumExpandedBytes - $Total) -CompressedSize $Selected.Entry.CompressedSize -UncompressedSize $Selected.Entry.Length
      } catch {
        if ($OutputStream) { $OutputStream.Dispose(); $OutputStream = $null }
        Remove-Item -LiteralPath $Target.Path -Force -ErrorAction SilentlyContinue
        throw
      } finally {
        if ($OutputStream) { $OutputStream.Dispose() }
        if ($Range) { $Range.Dispose() }
        $Source.Dispose()
      }
      $Output = Get-Item -LiteralPath $Target.Path
    } else {
      $Output = Export-InstallerArchiveEntry -Entry $Selected.Entry -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $Total) -CollisionAction Overwrite
    }
    $Total += $Output.Length; $Files.Add($Output)
  }
  return [pscustomobject][ordered]@{ Files = @($Files); ExpandedBytes = $Total; EntryCount = $Selection.Count }
}

function Get-AKInstallerNativePayloadEvidence {
  <#
  .SYNOPSIS
    Analyze the installed primary executable and bounded adjacent native files.
  .PARAMETER Context
    Open native archive context.
  .PARAMETER Table
    Decoded project table.
  .PARAMETER Catalog
    Installed-relative payload catalog.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)]$Table,
    [Parameter(Mandatory)][object[]]$Catalog
  )

  $Diagnostics = [Collections.Generic.List[object]]::new()
  $MainName = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA67A')
  $Main = $Catalog | Where-Object { $_.FileName -ieq $MainName } | Select-Object -First 1
  if (-not $Main) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Architecture.MainExecutableUnresolved' -Source 'AKInstaller' -Message 'The compiled primary executable was not found in the installed-file catalog; payload architecture remains unresolved.' -Kind Incomplete -Areas Metadata -AffectedFields @('Architecture', 'Dependencies') -Evidence $MainName))
    return [pscustomobject]@{ ArchitectureInfo = $null; DependencyInfo = $null; Diagnostics = @($Diagnostics) }
  }
  $Directory = [IO.Path]::GetDirectoryName($Main.Path)
  $Selection = @($Main) + @($Catalog | Where-Object {
      $_ -ne $Main -and [IO.Path]::GetDirectoryName($_.Path) -ieq $Directory -and [IO.Path]::GetExtension($_.Path) -iin @('.dll', '.exe')
    } | Select-Object -First 127)
  if (($Selection | Measure-Object Length -Sum).Sum -gt 268435456) { $Selection = @($Main) }
  $TemporaryDirectory = New-TempFolder
  try {
    $Expanded = Export-AKInstallerEntryMap -Context $Context -Catalog $Selection -DestinationPath $TemporaryDirectory -CollisionAction Rename -MaximumExpandedBytes 268435456 -MaximumEntries 128
    $MainPath = Join-Path $TemporaryDirectory $Main.Path
    if (-not (Test-Path -LiteralPath $MainPath -PathType Leaf)) { throw 'The primary payload executable was not materialized.' }
    $Related = @($Expanded.Files.FullName | Where-Object { $_ -ine $MainPath })
    $ArchitectureInfo = Get-PEArchitectureInfo -Path $MainPath -RelatedFile @($Related | Where-Object { [IO.Path]::GetExtension($_) -ieq '.dll' })
    $DependencyInfo = Get-PEDependencyInfo -Path $MainPath -RelatedFile $Related
    return [pscustomobject]@{ ArchitectureInfo = $ArchitectureInfo; DependencyInfo = $DependencyInfo; Diagnostics = @($Diagnostics) }
  } catch {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Architecture.AnalysisFailed' -Source 'AKInstaller' -Message "Installed payload architecture or dependency analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('Architecture', 'Dependencies')))
    return [pscustomobject]@{ ArchitectureInfo = $null; DependencyInfo = $null; Diagnostics = @($Diagnostics) }
  } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-AKInstallerMsiSwitchSet {
  <#
  .SYNOPSIS
    Build the command-line switch set shared by AKInstallerMSI wrapper routes.
  .PARAMETER InstallLocationProperty
    Optional public MSI directory property connected to the selected payload.
  .OUTPUTS
    An ordered dictionary containing source-backed wrapper switches.
  #>
  [OutputType([System.Collections.IDictionary])]
  param([AllowNull()][AllowEmptyString()][string]$InstallLocationProperty)

  # Forward reboot suppression as an MSI property. The documented @norestart
  # translation becomes /norestart in a position that real wrappers reject.
  $InstallerSwitches = [ordered]@{
    Silent             = '/silent 2 /msiparam "REBOOT=ReallySuppress"'
    SilentWithProgress = '/msilimitui 67 /msiparam "REBOOT=ReallySuppress"'
    Log                = '/logfile'
  }
  if ($InstallLocationProperty) {
    $InstallerSwitches.InstallLocation = "/msiparam `"$InstallLocationProperty='<INSTALLPATH>'`""
  }
  return $InstallerSwitches
}

function Get-AKInstallerMsiBootstrapperInfo {
  param ([Parameter(Mandatory)]$Context)

  $Diagnostics = [Collections.Generic.List[object]]::new()
  $OuterArchitectureInfo = Get-PEArchitectureInfo -Path $Context.File.FullName
  $ConfigEntry = $Context.Entries | Where-Object Key -CEQ 'Config.ini_' | Select-Object -First 1
  $ConfigText = Read-InstallerArchiveEntryText -Entry $ConfigEntry -MaximumBytes 4194304 -Encoding ([Text.Encoding]::Default)
  $Config = ConvertFrom-Ini -Content $ConfigText -DuplicateKeyAction Last -IgnoreComments
  $Main = $Config['Main']
  if (-not $Main) { throw 'AKInstallerMSI Config.ini lacks the Main section.' }
  $LaunchConditions = @(Get-AKInstallerMsiLaunchCondition -Configuration $Config)
  $Nested = [Collections.Generic.List[object]]::new()
  $PayloadCatalog = [Collections.Generic.List[object]]::new()
  $ExternalPayloads = [Collections.Generic.List[object]]::new()
  $TemporaryDirectory = New-TempFolder
  try {
    $FileCount = 0; [void][int]::TryParse([string]$Main['FileCount'], [ref]$FileCount)
    for ($Index = 1; $Index -le $FileCount; $Index++) {
      $Section = $Config["File$Index"]
      if (-not $Section) { continue }
      $LogicalName = [string]$Section['Path']
      $FilePolicy = Get-AKInstallerMsiFilePolicy -Section $Section
      $ArchiveEntry = $Context.Entries | Where-Object { $_.Key -ceq "File${Index}${LogicalName}_" -or $_.Key -ceq "File${Index}$([IO.Path]::GetFileName($LogicalName))_" } | Select-Object -First 1
      if (-not $ArchiveEntry) {
        $ExternalUri = $null
        if ([Uri]::TryCreate($LogicalName, [UriKind]::Absolute, [ref]$ExternalUri) -and $ExternalUri.Scheme -cin @('http', 'https')) {
          $ExternalPayloads.Add([pscustomobject][ordered]@{ Index = $Index; Path = $LogicalName; Uri = $ExternalUri.AbsoluteUri; Source = 'External'; StartMode = $Section['Start']; Parameters = Get-AKInstallerLocalizedIniValue -Section $Section -Name 'Parameter'; IsMsi = [IO.Path]::GetExtension($ExternalUri.AbsolutePath) -ieq '.msi'; Policy = $FilePolicy; Configuration = [pscustomobject]$Section })
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstallerMSI.Dependencies.ExternalPayload' -Source 'AKInstallerMSI' -Message "Configured prerequisite '$LogicalName' is downloaded at runtime and is not part of the embedded extraction catalog." -Kind Information -Areas Extraction, Installability -AffectedFields Dependencies -Evidence ([ordered]@{ Uri = $ExternalUri.AbsoluteUri; Index = $Index })))
          continue
        }
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstallerMSI.Payload.ConfiguredFileMissing' -Source 'AKInstallerMSI' -Message "Configured payload '$LogicalName' is not embedded in the bootstrapper." -Kind Incomplete -Areas Extraction, Installability -AffectedFields @('NestedInstallerFiles', 'Dependencies') -Evidence ([ordered]@{ File = $LogicalName; Index = $Index })))
        continue
      }
      $PayloadCatalog.Add([pscustomobject][ordered]@{ Index = $Index; Path = $LogicalName; ArchiveKey = $ArchiveEntry.Key; Length = $ArchiveEntry.Length; StartMode = $Section['Start']; Parameters = Get-AKInstallerLocalizedIniValue -Section $Section -Name 'Parameter'; IsMsi = [IO.Path]::GetExtension($LogicalName) -ieq '.msi'; Policy = $FilePolicy })
      if ([IO.Path]::GetExtension($LogicalName) -ine '.msi') { continue }
      $MsiPath = Join-Path $TemporaryDirectory ("$Index-" + [IO.Path]::GetFileName($LogicalName))
      $null = Export-InstallerArchiveEntry -Entry $ArchiveEntry -DestinationPath $MsiPath -MaximumBytes ([Math]::Max(1L, $ArchiveEntry.Length)) -CollisionAction Overwrite
      $MsiInfo = Get-MsiInstallerInfo -Path $MsiPath
      $Nested.Add([pscustomobject][ordered]@{ Index = $Index; Path = $LogicalName; ArchiveKey = $ArchiveEntry.Key; Policy = $FilePolicy; Configuration = [pscustomobject]$Section; Info = $MsiInfo })
    }
  } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
  if ($Nested.Count -eq 0) { throw 'AKInstallerMSI contains no parseable configured MSI payload.' }
  $ConfiguredProductCode = [string](Get-AKInstallerLocalizedIniValue -Section $Main -Name 'ProductCode')
  $Primary = $Nested | Where-Object { $_.Info.ProductCode -ceq $ConfiguredProductCode -or [string]$_.Configuration.ProductCode -ceq $ConfiguredProductCode } | Select-Object -First 1
  $PrimarySelection = $Primary ? 'ConfiguredProductCode' : $null
  if (-not $Primary) {
    $Primary = $Nested | Where-Object { [string]$_.Configuration.Start -eq '2' } | Select-Object -First 1
    if ($Primary) { $PrimarySelection = 'StartMode2' }
  }
  if (-not $Primary -and $Nested.Count -eq 1) { $Primary = $Nested[0]; $PrimarySelection = 'OnlyNestedMsi' }
  if (-not $Primary) {
    throw 'AKInstallerMSI contains multiple configured MSI payloads but does not identify the primary product.'
  }
  $Info = $Primary.Info
  if (-not $Info.Scope) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstallerMSI.Scope.ContextDependent' -Source 'AKInstallerMSI' -Message 'The selected MSI permits a context-dependent installation scope; do not author a fixed scope without package or VM evidence.' -Kind Ambiguous -Areas Metadata, Installability -AffectedFields Scope -Evidence ([ordered]@{ AllUsers = $Info.AllUsers })))
  }
  $AppsEntry = [ordered]@{ ProductCode = $Info.ProductCode; InstallerType = $Info.InstallerType }
  if ($Info.UpgradeCode) { $AppsEntry.UpgradeCode = $Info.UpgradeCode }
  if ($Info.DisplayName) { $AppsEntry.DisplayName = $Info.DisplayName }
  if ($Info.DisplayVersion) { $AppsEntry.DisplayVersion = $Info.DisplayVersion }
  if ($Info.Publisher) { $AppsEntry.Publisher = $Info.Publisher }
  $AppsEntries = $Info.WritesAppsAndFeaturesEntry -and $Info.ProductCode ? @([pscustomobject]$AppsEntry) : @()
  $Prerequisites = @($PayloadCatalog | Where-Object { -not $_.IsMsi }) + @($ExternalPayloads)
  if ($Prerequisites.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstallerMSI.Dependencies.BootstrapperPayloads' -Source 'AKInstallerMSI' -Message 'The bootstrapper contains non-MSI prerequisite or helper payloads; they are returned as evidence and are not projected directly to manifest Dependencies.' -Kind Information -Areas Installability -AffectedFields Dependencies -Evidence @($Prerequisites.Path)))
  }
  $ConditionalPayloads = @($Prerequisites | Where-Object { $_.Policy.Conditions.Count -gt 0 -or $_.Policy.DetectionTests.Count -gt 0 })
  if ($ConditionalPayloads.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstallerMSI.Dependencies.ConditionalPayloads' -Source 'AKInstallerMSI' -Message 'Some bootstrapper prerequisites are selected by runtime conditions or detection tests; applicability requires target-system evidence.' -Kind ManualValidation -Areas Installability -AffectedFields Dependencies -Evidence @($ConditionalPayloads.Path)))
  }
  $InstallerSwitches = ConvertTo-AKInstallerMsiSwitchSet -InstallLocationProperty $Info.InstallLocationProperty
  return [pscustomobject][ordered]@{
    Path = $Context.File.FullName; Family = 'AKInstallerMSI'; ProductLine = 'AKInstallerMSI'; Route = $Context.Route; InstallerType = 'exe'
    FormatGeneration = $Context.Route -ceq 'AKInstallerMSI/BootstrapperLegacy' ? 'BootstrapperLegacyAkiZip' : 'BootstrapperZip'; InstallerBuilderVersion = $Info.InstallerBuilderVersion
    DisplayName = $Info.DisplayName; ProductVersion = $Info.DisplayVersion; DisplayVersion = $Info.DisplayVersion; Publisher = $Info.Publisher; ProductCode = $Info.ProductCode; UpgradeCode = $Info.UpgradeCode
    Scope = $Info.Scope; SupportedScopes = @($Info.Scope | Where-Object { $_ }); SupportsDualScope = $false; ElevationRequirement = $Info.ElevationRequirement
    DefaultInstallLocation = $Info.DefaultInstallLocation; InstallLocation = $Info.DefaultInstallLocation; InstallLocationSwitch = $Info.InstallLocationSwitch
    WritesAppsAndFeaturesEntry = $Info.WritesAppsAndFeaturesEntry; AppsAndFeaturesProductCode = $Info.AppsAndFeaturesProductCode; AppsAndFeaturesInstallerType = $Info.InstallerType; AppsAndFeaturesEntries = $AppsEntries
    RegistryView = $Info.PackageArchitecture -eq 'x86' ? '32-bit' : ($Info.PackageArchitecture -in 'x64', 'arm64' ? '64-bit' : 'default'); RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Context.File.FullName
    PackageArchitecture = $Info.PackageArchitecture; SupportedArchitectures = @($Info.SupportedArchitectures); OuterArchitectureInfo = $OuterArchitectureInfo; Protocols = @($Info.Protocols); FileExtensions = @($Info.FileExtensions)
    InstallModes = @('interactive', 'silent', 'silentWithProgress'); InstallerSwitches = $InstallerSwitches
    SupportedCommandLineSwitches = @('/silent', '/language', '/logfile', '/replaceparam', '/msilimitui', '/msiparam', '/uninstall')
    DocumentedReturnCodes = @(0, 1602, 1603, 1618, 1625, 1638, 3010, 1641)
    Configuration = [pscustomobject]$Config; LaunchConditions = $LaunchConditions; NestedInstallers = @($Nested); PrimaryNestedInstaller = $Primary; PrimaryNestedInstallerSelection = $PrimarySelection; PayloadFiles = @($PayloadCatalog); PrerequisitePayloads = $Prerequisites; ExecutedPayloads = @(@($PayloadCatalog) + @($ExternalPayloads))
    PayloadEncrypted = $true; PayloadDecryptionSucceeded = $true; CanExpand = $true
    Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic @($Info.Diagnostics, $Diagnostics)); UnresolvedFields = [string[]]@($Info.Scope ? @() : @('Scope'))
  }
}

function ConvertTo-AKInstallerMsiInfoResult {
  param ([Parameter(Mandatory)]$Context)
  $Info = $Context.MsiInfo
  $OuterArchitectureInfo = Get-PEArchitectureInfo -Path $Context.File.FullName
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Diagnostic in @($Info.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
  if (-not $Info.Scope) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstallerMSI.Scope.ContextDependent' -Source 'AKInstallerMSI' -Message 'The embedded MSI permits a context-dependent installation scope; do not author a fixed scope without package or VM evidence.' -Kind Ambiguous -Areas Metadata, Installability -AffectedFields Scope -Evidence ([ordered]@{ AllUsers = $Info.AllUsers })))
  }
  $Entry = [ordered]@{ ProductCode = $Info.ProductCode; InstallerType = $Info.InstallerType }
  if ($Info.UpgradeCode) { $Entry.UpgradeCode = $Info.UpgradeCode }
  if ($Info.DisplayName) { $Entry.DisplayName = $Info.DisplayName }
  if ($Info.DisplayVersion) { $Entry.DisplayVersion = $Info.DisplayVersion }
  if ($Info.Publisher) { $Entry.Publisher = $Info.Publisher }
  $AppsEntries = $Info.WritesAppsAndFeaturesEntry -and $Info.ProductCode ? @([pscustomobject]$Entry) : @()
  $InstallerSwitches = ConvertTo-AKInstallerMsiSwitchSet -InstallLocationProperty $Info.InstallLocationProperty
  [pscustomobject][ordered]@{
    Path = $Context.File.FullName; Family = 'AKInstallerMSI'; ProductLine = 'AKInstallerMSI'; Route = $Context.Route; InstallerType = 'exe'
    FormatGeneration = 'EmbeddedMsi'; InstallerBuilderVersion = $Info.InstallerBuilderVersion
    DisplayName = $Info.DisplayName; ProductVersion = $Info.DisplayVersion; DisplayVersion = $Info.DisplayVersion; Publisher = $Info.Publisher; ProductCode = $Info.ProductCode; UpgradeCode = $Info.UpgradeCode
    Scope = $Info.Scope; SupportedScopes = @($Info.Scope | Where-Object { $_ }); SupportsDualScope = $false; ElevationRequirement = $Info.ElevationRequirement
    DefaultInstallLocation = $Info.DefaultInstallLocation; InstallLocation = $Info.DefaultInstallLocation; InstallLocationSwitch = $Info.InstallLocationSwitch
    WritesAppsAndFeaturesEntry = $Info.WritesAppsAndFeaturesEntry; AppsAndFeaturesProductCode = $Info.AppsAndFeaturesProductCode; AppsAndFeaturesInstallerType = $Info.InstallerType; AppsAndFeaturesEntries = $AppsEntries
    RegistryView = $Info.PackageArchitecture -eq 'x86' ? '32-bit' : ($Info.PackageArchitecture -in 'x64', 'arm64' ? '64-bit' : 'default'); RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Context.File.FullName
    PackageArchitecture = $Info.PackageArchitecture; SupportedArchitectures = @($Info.SupportedArchitectures); OuterArchitectureInfo = $OuterArchitectureInfo; Protocols = @($Info.Protocols); FileExtensions = @($Info.FileExtensions)
    InstallModes = @('interactive', 'silent', 'silentWithProgress'); InstallerSwitches = $InstallerSwitches
    SupportedCommandLineSwitches = @('/silent', '/language', '/logfile', '/replaceparam', '/msilimitui', '/msiparam', '/uninstall')
    DocumentedReturnCodes = @(0, 1602, 1603, 1618, 1625, 1638, 3010, 1641)
    NestedInstallers = @([pscustomobject][ordered]@{ Path = 'embedded.msi'; ArchiveOffset = $Context.ArchiveOffset; ArchiveLength = $Context.ArchiveLength; Info = $Info }); PrimaryNestedInstaller = $Info
    PayloadFiles = @([pscustomobject][ordered]@{ Path = 'embedded.msi'; ArchiveOffset = $Context.ArchiveOffset; Length = $Context.ArchiveLength; IsMsi = $true }); PayloadEncrypted = $false; PayloadDecryptionSucceeded = $true; CanExpand = $true
    Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics); UnresolvedFields = [string[]]@($Info.Scope ? @() : @('Scope'))
  }
}

function Get-AKInstallerNativeInfo {
  param ([Parameter(Mandatory)]$Context)

  $Table = $Context.ProjectTable
  $IsClassicRoute = $Context.Route -ceq 'AKInstaller/NativeClassicGZip'
  $VariableContext = Get-AKInstallerNativeVariableContext -Table $Table
  $Variables = $VariableContext.Values
  $ProductName = [string]$Variables.PRODUCTNAME
  $ProductCode = [string]$Variables.PRODUCTCODE
  $ProductVersion = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA03A')
  $Publisher = [string](Get-AKInstallerRecordValue -Table $Table -Name 'STPLAA04A')
  $DefaultInstallLocation = $VariableContext.DefaultInstallLocation
  $OuterArchitectureInfo = Get-PEArchitectureInfo -Path $Context.File.FullName
  # Registry writes execute in the native setup runtime. Keep this evidence
  # separate from installed payload architecture because a 32-bit bootstrapper
  # can install a 64-bit application.
  $RegistryView = $OuterArchitectureInfo.NativeArchitecture -eq 'x86' ? '32-bit' : ($OuterArchitectureInfo.NativeArchitecture -in 'x64', 'arm64' ? '64-bit' : $null)
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  foreach ($Row in $Table.RegistryRows) {
    if ($Row.Create -eq $false) { continue }
    $Path = Resolve-AKInstallerVariable -Value $Row.Path -Variables $Variables
    if ([string]::IsNullOrWhiteSpace($Path)) { continue }
    if ($Path -match '^(?<Root>HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_USERS)\\(?<Path>.+)$') {
      $Root = switch ($Matches.Root) { 'HKEY_CLASSES_ROOT' { 'HKCR' }; 'HKEY_CURRENT_USER' { 'HKCU' }; 'HKEY_LOCAL_MACHINE' { 'HKLM' }; 'HKEY_USERS' { 'HKU' } }
      $Remainder = $Matches.Path
    } elseif ($Path -match '^(?<Token>\d+)\\(?<Path>.+)$') {
      $Root = switch ($Matches.Token) { '1' { 'HKCR' }; '2' { 'HKCU' }; '3' { 'HKLM' }; '4' { 'HKU' }; default { $null } }
      $Remainder = $Matches.Path
      if (-not $Root) { continue }
    } else { continue }
    $Separator = $Remainder.LastIndexOf('\')
    if ($Separator -lt 0) { continue }
    $Key = $Remainder.Substring(0, $Separator)
    $Name = $Remainder.Substring($Separator + 1)
    if ($Name -ceq '(Standard)') { $Name = '' }
    $TypeCode = $null -ne $Row.TypeCode ? [int]$Row.TypeCode : 1
    $RegistryType = switch ($TypeCode) { 2 { 'REG_DWORD' }; 3 { 'REG_BINARY' }; default { 'REG_SZ' } }
    if ($RegistryType -eq 'REG_BINARY') {
      $Value = $Row.Fields.'05' -is [byte[]] ? $Row.Fields.'05' : [byte[]]::new(0)
    } elseif ($RegistryType -eq 'REG_DWORD') {
      $ParsedValue = 0u
      $Value = [uint32]::TryParse([string]$Row.Value, [ref]$ParsedValue) ? $ParsedValue : $Row.Value
    } else {
      $Value = $Row.Value -is [string] ? (Resolve-AKInstallerVariable -Value ([string]$Row.Value) -Variables $Variables) : $Row.Value
      # The classic runtime normalizes INSTALLDIR without a trailing separator,
      # then appends one to the quoted directory argument consumed by its shared
      # AKDeInstall.exe. Preserve that observed command spelling without changing
      # unrelated registry strings that also reference INSTALLDIR.
      if ($IsClassicRoute -and [string]$Row.Value -match '(?i)<INSTALLDIR>"$' -and [string]$Value -match '"$') {
        $Value = ([string]$Value).Insert(([string]$Value).Length - 1, '\')
      }
    }
    $RegistryWrites.Add([pscustomobject][ordered]@{
        Hive = $Root; Root = $Root; View = $RegistryView; Key = $Key; Name = $Name; Value = $Value; Type = $RegistryType
        Create = $Row.Create; RemoveOnUninstall = $Row.RemoveOnUninstall; OnlyIfNotExists = $Row.OnlyIfNotExists
        IgnoreErrors = $Row.IgnoreErrors; NoTrailingSlash = $Row.NoTrailingSlash; ConditionValue = $Row.ConditionValue
        Source = "AKInstaller compiled registry row $($Row.Index)"
      })
  }
  $ArpInfo = Get-AKInstallerNativeArpInfo -RegistryWrite @($RegistryWrites) -CompiledProductCode $ProductCode
  $PrimaryArp = $ArpInfo.PrimaryEntry
  $ArpValues = $PrimaryArp ? $PrimaryArp.Values : $null
  $VisibleScopes = @($ArpInfo.VisibleEntries.Scope | Where-Object { $_ } | Sort-Object -Unique)
  $Scope = $VisibleScopes.Count -eq 1 ? $VisibleScopes[0] : $null
  $VisibleProductCode = $PrimaryArp ? $PrimaryArp.ProductCode : $null
  if ($Scope) { $Variables = (Get-AKInstallerNativeVariableContext -Table $Table -Scope $Scope).Values }
  $AssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite @($RegistryWrites)
  $PayloadCatalog = @(Get-AKInstallerNativePayloadCatalog -Table $Table -Variables $Variables -DefaultInstallLocation $DefaultInstallLocation -Entry @($Context.Entries))
  $SystemEffects = Get-AKInstallerNativeSystemEffectInfo -Table $Table -Variables $Variables
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Diagnostic in $AssociationInfo.Diagnostics) { $Diagnostics.Add($Diagnostic) }
  if ($ArpInfo.VisibleEntries.Count -eq 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.ARP.VisibleEntryUnresolved' -Source 'AKInstaller' -Message 'The compiled registry table does not prove one visible Apps & Features entry for this package.' -Kind Incomplete -Areas Metadata, Installability -AffectedFields @('ProductCode', 'Scope', 'AppsAndFeaturesEntries')))
  } elseif (-not $Scope) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.ARP.ScopeAmbiguous' -Source 'AKInstaller' -Message 'The compiled uninstall registration uses mixed or unsupported registry roots, so one installation scope cannot be selected.' -Kind Ambiguous -Areas Metadata, Installability -AffectedFields Scope -Evidence $VisibleScopes))
  }
  if ($ArpInfo.VisibleEntries.Count -gt 1 -and -not $PrimaryArp) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.ARP.MultipleVisibleEntries' -Source 'AKInstaller' -Message 'The compiled registry table writes multiple visible Apps & Features entries and does not identify one primary ProductCode.' -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence @($ArpInfo.VisibleEntries.ProductCode)))
  }
  if ($Table.MalformedRecords.Count -gt 0 -or $Table.DuplicateRecords.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Table.MalformedRecords' -Source 'AKInstaller' -Message 'Some marker-like native table records were malformed or duplicated and were excluded from projected evidence.' -Kind Incomplete -Areas Metadata, Extraction -Evidence ([ordered]@{ Malformed = @($Table.MalformedRecords); Duplicates = @($Table.DuplicateRecords) })))
  }
  $SizeMismatches = @($PayloadCatalog | Where-Object SizeMatchesPhysical -CEQ $false)
  if ($SizeMismatches.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Payload.SizeMismatch' -Source 'AKInstaller' -Message 'One or more compiled file sizes disagree with the corresponding physical payload records; physical lengths are used for bounded extraction.' -Kind Invalid -Areas Metadata, Extraction -AffectedFields @('NestedInstallerFiles', 'Architecture') -Evidence @($SizeMismatches | Select-Object Path, ArchiveKey, DeclaredLength, PhysicalLength)))
  }
  if ($Table.Files | Where-Object { $_.Class -eq 'Installed' -and -not [string]::IsNullOrWhiteSpace($_.Condition) }) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Payload.ConditionalFiles' -Source 'AKInstaller' -Message 'Some installed-file rows contain compiled conditions; the catalog preserves those conditions and extraction does not evaluate runtime state.' -Kind ManualValidation -Areas Extraction, Installability -AffectedFields @('NestedInstallerFiles', 'Dependencies')))
  }
  $RuntimeConditions = @($SystemEffects.Shortcuts.Condition + $SystemEffects.IniFileOperations.Condition + $SystemEffects.ExecutedPayloads.Condition + $SystemEffects.LaunchConditions.Condition + $SystemEffects.CompiledProperties.Condition + $SystemEffects.FileOperations.Condition | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
  if ($RuntimeConditions.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Conditions.RuntimeEvaluationRequired' -Source 'AKInstaller' -Message 'Compiled operation conditions are preserved but require runtime properties and are not evaluated during static parsing.' -Kind ManualValidation -Areas Installability -Evidence $RuntimeConditions))
  }
  if ($SystemEffects.ExecutedPayloads.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.SystemEffects.ExecutedPayloads' -Source 'AKInstaller' -Message 'The setup launches prerequisite or custom payloads whose side effects and applicability require separate analysis.' -Kind ManualValidation -Areas Installability, Security -AffectedFields Dependencies -Evidence @($SystemEffects.ExecutedPayloads.Path)))
  }
  $InvalidFileOperations = @($SystemEffects.FileOperations | Where-Object { -not $_.IsDecoded -or -not $_.IsStructurallyValid })
  if ($InvalidFileOperations.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.SystemEffects.FileOperationUnsupported' -Source 'AKInstaller' -Message 'One or more compiled file-operation records contain an unknown code or malformed path tuple and remain raw evidence.' -Kind Unsupported -Areas Extraction, Installability -Evidence @($InvalidFileOperations.EncodedOperation)))
  }
  if ($SystemEffects.ExtensionModules.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.SystemEffects.ExtensionSideEffectsOpaque' -Source 'AKInstaller' -Message 'The setup loads compiled extension DLLs. Their descriptors and payload keys are available, but exported-function side effects require separate static analysis or VM validation.' -Kind ManualValidation -Areas Installability, Security -Evidence @($SystemEffects.ExtensionModules.Identifier)))
  }
  $PayloadEvidence = Get-AKInstallerNativePayloadEvidence -Context $Context -Table $Table -Catalog @($PayloadCatalog)
  foreach ($Diagnostic in $PayloadEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) }
  $PackageArchitectureInfo = $PayloadEvidence.ArchitectureInfo
  $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Context.File.FullName
  $ElevationRequirement = $RequestedExecutionLevel -eq 'requireAdministrator' ? 'elevationRequired' : $null
  $EffectiveInstallLocation = [string](${PrimaryArp}?.InstallLocation ?? $DefaultInstallLocation)
  if ($EffectiveInstallLocation.Length -gt 3) { $EffectiveInstallLocation = $EffectiveInstallLocation.TrimEnd('\') }
  if ($Scope -eq 'machine' -and -not $ElevationRequirement) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Elevation.RuntimePolicyUnresolved' -Source 'AKInstaller' -Message 'Machine-scope registry evidence does not establish whether this runtime must be launched elevated or elevates itself.' -Kind ManualValidation -Areas Installability -AffectedFields ElevationRequirement -Evidence $RequestedExecutionLevel))
  }
  if ($IsClassicRoute) {
    # The classic runtime exposes an internal silent-state variable, but this
    # artifact contains no source-backed command-line vocabulary. Do not apply
    # the documented modern native switches to an older structural route.
    $InstallModes = @('interactive')
    $InstallerSwitches = [ordered]@{}
    $SupportedCommandLineSwitches = @()
    $DocumentedReturnCodes = @()
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'AKInstaller.Classic.CommandLineBehaviorUnresolved' -Source 'AKInstaller' -Message 'The classic native runtime does not expose enough structured evidence to identify unattended-installation switches or process return-code behavior. Validate command-line behavior in a VM.' -Kind ManualValidation -Areas Installability -AffectedFields InstallModes, InstallerSwitches, ExpectedReturnCodes -Evidence $Context.FooterFields))
  } else {
    $InstallModes = @('interactive', 'silent')
    $InstallerSwitches = [ordered]@{ Silent = '/silent 1 /NoReboot'; SilentWithProgress = '/silent 1 /NoReboot'; InstallLocation = '/installdir "<INSTALLPATH>"' }
    $SupportedCommandLineSwitches = @('/silent', '/eula', '/installdir', '/logfile', '/NoReboot', '/rn', '/languageid', '/features', '/auto', '/uninstall', '/uninstallex')
    $DocumentedReturnCodes = @(0, 3010, 1641)
  }
  $UnresolvedFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  if (-not $Scope) { $null = $UnresolvedFields.Add('Scope') }
  if (-not $PackageArchitectureInfo) { $null = $UnresolvedFields.Add('Architecture') }
  if ($ArpInfo.VisibleEntries.Count -gt 0 -and -not $VisibleProductCode) { $null = $UnresolvedFields.Add('ProductCode') }
  return [pscustomobject][ordered]@{
    Path = $Context.File.FullName; Family = 'AKInstaller'; ProductLine = 'AKInstaller'; Route = $Context.Route; InstallerType = 'exe'
    FormatGeneration = $Context.Route -ceq 'AKInstaller/NativeClassicGZip' ? "NativeClassicGZipTable$($Table.FormatVersion)" : ($Context.TableProfile -ceq 'LegacyXor' ? "NativeLegacyTable$($Table.FormatVersion)" : "NativeTable$($Table.FormatVersion)"); EngineVersion = $Table.EngineVersion; TableStringProfile = $Table.StringProfile
    # Keep package identity separate from ARP identity. Manifest updating consumes
    # DisplayVersion and Publisher as uninstall-entry evidence, so falling back to
    # compiled values would fabricate fields that classic packages can omit.
    DisplayName = ${ArpValues}?.DisplayName; ProductName = $ProductName; ProductVersion = $ProductVersion; DisplayVersion = ${ArpValues}?.DisplayVersion; Publisher = ${ArpValues}?.Publisher; CompiledPublisher = $Publisher
    ProductCode = $VisibleProductCode; UpgradeCode = $null; Scope = $Scope; SupportedScopes = @($VisibleScopes); SupportsDualScope = $false
    RequestedExecutionLevel = $RequestedExecutionLevel; ElevationRequirement = $ElevationRequirement
    DefaultInstallLocation = $EffectiveInstallLocation; InstallLocation = $EffectiveInstallLocation; UninstallString = ${PrimaryArp}?.UninstallString; QuietUninstallString = ${PrimaryArp}?.QuietUninstallString; DisplayIcon = ${PrimaryArp}?.DisplayIcon
    SystemComponent = $PrimaryArp ? [bool]$PrimaryArp.SystemComponent : $false; RegistryView = ${PrimaryArp}?.View ?? $RegistryView; RegistryViewEvidence = $RegistryView ? 'OuterRuntimeDefault' : $null
    WritesAppsAndFeaturesEntry = $ArpInfo.VisibleEntries.Count -gt 0; AppsAndFeaturesProductCode = $VisibleProductCode; AppsAndFeaturesInstallerType = $ArpInfo.VisibleEntries.Count -gt 0 ? 'exe' : $null; AppsAndFeaturesEntries = @($ArpInfo.AppsAndFeaturesEntries)
    AppsAndFeaturesEvidence = @($ArpInfo.Entries); HiddenArpEntries = @($ArpInfo.HiddenEntries)
    RegistryWrites = @($RegistryWrites); RegistryTableRows = @($Table.RegistryRows); Protocols = @($AssociationInfo.Protocols); FileExtensions = @($AssociationInfo.FileExtensions); RegistryAssociationInfo = $AssociationInfo
    Shortcuts = @($SystemEffects.Shortcuts); IniFileOperations = @($SystemEffects.IniFileOperations); ExecutedPayloads = @($SystemEffects.ExecutedPayloads); LaunchConditions = @($SystemEffects.LaunchConditions); Permissions = @($SystemEffects.Permissions)
    DirectoryAttributeOperations = @($SystemEffects.DirectoryAttributeOperations); CompiledProperties = @($SystemEffects.CompiledProperties); ExtensionModules = @($SystemEffects.ExtensionModules); FileOperations = @($SystemEffects.FileOperations)
    PackageArchitecture = ${PackageArchitectureInfo}?.RecommendedWinGetArchitecture; SupportedArchitectures = @(${PackageArchitectureInfo}?.SupportedArchitectures); OuterArchitectureInfo = $OuterArchitectureInfo; PayloadArchitectureInfo = $PayloadEvidence.ArchitectureInfo; DependencyInfo = $PayloadEvidence.DependencyInfo
    RecommendedPackageDependencies = $PayloadEvidence.DependencyInfo ? @($PayloadEvidence.DependencyInfo.RecommendedPackageDependencies) : @()
    InstallModes = $InstallModes; InstallerSwitches = $InstallerSwitches; SupportedCommandLineSwitches = $SupportedCommandLineSwitches
    DocumentedReturnCodes = $DocumentedReturnCodes; ProjectTable = $Table; PayloadFiles = @($PayloadCatalog); TemporaryPayloads = @($Table.Files | Where-Object Class -CEQ 'Temporary')
    PayloadEncrypted = $Context.Route -cne 'AKInstaller/NativeClassicGZip'; PayloadDecryptionSucceeded = $true; CanExpand = @($PayloadCatalog).Count -gt 0
    Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics); UnresolvedFields = [string[]]@($UnresolvedFields | Sort-Object)
  }
}

function Get-AKInstallerInfo {
  <#
  .SYNOPSIS
    Read AKInstaller or AKInstallerMSI metadata, ARP, payload, switch, and system-effect evidence.
  .PARAMETER Path
    Path to an AKInstaller native setup or AKInstallerMSI bootstrapper. The installer is never executed.
  .OUTPUTS
    Provider-neutral parser metadata with structured Diagnostics and UnresolvedFields.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Context = $null
    try {
      $Context = Get-AKInstallerArchiveContext -Path $ResolvedPath
      if ($Context) {
        return $Context.Route.StartsWith('AKInstaller/Native', [StringComparison]::Ordinal) ? (Get-AKInstallerNativeInfo -Context $Context) : (Get-AKInstallerMsiBootstrapperInfo -Context $Context)
      }
    } finally { Close-AKInstallerContext -Context $Context }
    $Direct = Get-AKInstallerDirectMsiContext -Path $ResolvedPath
    if ($Direct) { return ConvertTo-AKInstallerMsiInfoResult -Context $Direct }
    throw 'The file does not contain a supported AKInstaller or AKInstallerMSI structure.'
  }
}

function Test-AKInstaller {
  <#
  .SYNOPSIS
    Test whether a PE contains a structurally valid AKInstaller route.
  .PARAMETER Path
    Candidate installer path.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $Context = $null
    try {
      $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      $Context = Get-AKInstallerArchiveContext -Path $ResolvedPath
      if ($Context) { return $true }
      return $null -ne (Get-AKInstallerDirectMsiContext -Path $ResolvedPath)
    } catch {
      return $false
    } finally {
      Close-AKInstallerContext -Context $Context
    }
  }
}

function Expand-AKInstaller {
  <#
  .SYNOPSIS
    Extract installed native payloads or AKInstallerMSI wrapper payloads without executing them.
  .PARAMETER Path
    Installer path.
  .PARAMETER DestinationPath
    Extraction root.
  .PARAMETER Name
    Wildcard over logical paths or file names. Omission selects every normal payload.
  .PARAMETER RawEntries
    Export physical archive names rather than installed/logical names.
  .PARAMETER CollisionAction
    Collision behavior. Prompt asks only after a collision occurs.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [switch]$RawEntries,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:AKInstallerMaximumExpandedBytes,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = $Script:AKInstallerMaximumEntries
  )
  process {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $Context = $null
    try {
      $Context = Get-AKInstallerArchiveContext -Path $ResolvedPath
      if ($Context) {
        if ($RawEntries) {
          $Catalog = @($Context.Entries | ForEach-Object { [pscustomobject]@{ Path = Join-Path '_akinstaller' $_.Key; ArchiveKey = $_.Key } })
        } elseif ($Context.Route.StartsWith('AKInstaller/Native', [StringComparison]::Ordinal)) {
          $Table = $Context.ProjectTable
          $VariableContext = Get-AKInstallerNativeVariableContext -Table $Table
          $Variables = $VariableContext.Values
          $DefaultInstallLocation = $VariableContext.DefaultInstallLocation
          $Catalog = @(Get-AKInstallerNativePayloadCatalog -Table $Table -Variables $Variables -DefaultInstallLocation $DefaultInstallLocation -Entry @($Context.Entries))
        } else {
          $ConfigEntry = $Context.Entries | Where-Object Key -CEQ 'Config.ini_' | Select-Object -First 1
          $Config = ConvertFrom-Ini -Content (Read-InstallerArchiveEntryText -Entry $ConfigEntry -MaximumBytes 4194304 -Encoding ([Text.Encoding]::Default)) -DuplicateKeyAction Last -IgnoreComments
          $Catalog = @()
          $Count = 0; [void][int]::TryParse([string]$Config.Main.FileCount, [ref]$Count)
          for ($Index = 1; $Index -le $Count; $Index++) {
            $LogicalName = [string]$Config["File$Index"].Path
            $Entry = $Context.Entries | Where-Object { $_.Key -ceq "File${Index}${LogicalName}_" -or $_.Key -ceq "File${Index}$([IO.Path]::GetFileName($LogicalName))_" } | Select-Object -First 1
            if ($Entry) { $Catalog += [pscustomobject]@{ Path = $LogicalName; ArchiveKey = $Entry.Key } }
          }
        }
        return Export-AKInstallerEntryMap -Context $Context -Catalog $Catalog -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries $MaximumEntries
      }
    } finally { Close-AKInstallerContext -Context $Context }

    $Direct = Get-AKInstallerDirectMsiContext -Path $ResolvedPath
    if (-not $Direct) { throw 'The file does not contain a supported AKInstaller or AKInstallerMSI structure.' }
    if (-not (Test-ExtractionPattern -Path 'embedded.msi' -Pattern $Name)) { return [pscustomobject]@{ Files = @(); ExpandedBytes = 0L; EntryCount = 0 } }
    if ($Direct.ArchiveLength -gt $MaximumExpandedBytes) { throw "The AKInstaller selection exceeds the $MaximumExpandedBytes-byte output limit." }
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath ($RawEntries ? '_akinstaller\embedded.msi' : 'embedded.msi') -CollisionAction $CollisionAction
    if (-not $Target.ShouldWrite) { return [pscustomobject]@{ Files = @(); ExpandedBytes = 0L; EntryCount = 1 } }
    $File = Export-InstallerArchiveRange -Path $ResolvedPath -Offset $Direct.ArchiveOffset -Length $Direct.ArchiveLength -DestinationPath $Target.Path -CollisionAction Overwrite
    return [pscustomobject]@{ Files = @($File); ExpandedBytes = $File.Length; EntryCount = 1 }
  }
}

function Read-ProductVersionFromAKInstaller {
  <#
  .SYNOPSIS
    Read the packaged product version.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $Info = Get-AKInstallerInfo -Path $Path
    $Info.ProductVersion ?? $Info.DisplayVersion
  }
}

function Read-ProductNameFromAKInstaller {
  <#
  .SYNOPSIS
    Read the packaged product display name.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-AKInstallerInfo -Path $Path).DisplayName }
}

function Read-PublisherFromAKInstaller {
  <#
  .SYNOPSIS
    Read the packaged publisher.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-AKInstallerInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromAKInstaller {
  <#
  .SYNOPSIS
    Read the visible uninstall identity.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-AKInstallerInfo -Path $Path).ProductCode }
}

function Read-UpgradeCodeFromAKInstaller {
  <#
  .SYNOPSIS
    Read the nested MSI UpgradeCode when present.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-AKInstallerInfo -Path $Path).UpgradeCode }
}

function Read-ScopeFromAKInstaller {
  <#
  .SYNOPSIS
    Read statically proven installation scope.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-AKInstallerInfo -Path $Path).Scope }
}

function Read-ProtocolsFromAKInstaller {
  <#
  .SYNOPSIS
    Read literal protocol registrations.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string[]])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { @((Get-AKInstallerInfo -Path $Path).Protocols) }
}

function Read-FileExtensionsFromAKInstaller {
  <#
  .SYNOPSIS
    Read literal file-extension registrations.
  .PARAMETER Path
    AKInstaller or AKInstallerMSI path.
  #>
  [OutputType([string[]])] param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { @((Get-AKInstallerInfo -Path $Path).FileExtensions) }
}

Export-ModuleMember -Function Get-AKInstallerInfo, Test-AKInstaller, Expand-AKInstaller, Read-ProductVersionFromAKInstaller, Read-ProductNameFromAKInstaller, Read-PublisherFromAKInstaller, Read-ProductCodeFromAKInstaller, Read-UpgradeCodeFromAKInstaller, Read-ScopeFromAKInstaller, Read-ProtocolsFromAKInstaller, Read-FileExtensionsFromAKInstaller
