# SPDX-License-Identifier: Apache-2.0
# Static Wise Installation System parser. Supported routes:
#
#   PE -> .WISE section -> exact MSI CFB bytes -> CRC32
#   PE -> WiseScript overlay -> header Deflate members -> state-machine payloads
#   PE -> .rsrc slack PE -> WiseScript overlay -> .WISE MSI payload
#
# WiseScript state decoding uses the pinned MIT SabreTools reader. Dumplings owns
# PE/container discovery, bounds, decompression, CRC checks, nested selection,
# metadata projection, and extraction; no installer or payload is executed.
#
# Physical layouts consumed here (all integers little-endian):
#
#   MZ -> NE or PE host -> WiseScript overlay
#     +0x00  byte     optional DLL-name length
#     +...   uint32   flags and compressed-member sizes
#     +...   Deflate  WiseScript state bytes
#     +...   uint32   inflated-state CRC32
#     +...   repeated InstallFile Deflate records and CRC32 trailers
#
#   PE -> .WISE section
#     +0x18  uint32   MSI record length, including trailing CRC32
#     +...   bytes    metadata/padding ending at MSI CFB magic
#     +...   bytes    exact MSI CFB database
#     +...   uint32   MSI CRC32
#
# Format evidence and independently implemented bounds are grounded in the
# archived Wise builders and the MIT WiseUnpacker/SabreTools projects:
# https://github.com/mnadareski/WiseUnpacker
# https://github.com/SabreTools/SabreTools.Serialization
# https://archive.org/details/wise-installer

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:WiseMsiClassId = '{000C1084-0000-0000-C000-000000000046}'
$Script:WiseMaximumEmbeddedMsiBytes = 4294967296
$Script:WiseMaximumScriptBytes = 67108864
$Script:WiseMaximumPayloadBytes = 4294967296
$Script:WiseCfbMagic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)

function Import-WiseScriptReader {
  <#.SYNOPSIS Load the pinned MIT WiseScript model and reader.#>
  $AssetRoot = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets'
  $null = Import-InstallerManagedAssembly -Name 'SabreTools.IO.dll' -TypeName 'SabreTools.IO.Extensions.StreamExtensions' -AssetRoot $AssetRoot
  try {
    $null = Import-InstallerManagedAssembly -Name 'SabreTools.Serialization.dll' -TypeName 'SabreTools.Wrappers.WiseScript' -AssetRoot $AssetRoot
  } catch {
    # Add-Type can report an unrelated optional model while enumerating every
    # type after this multi-format assembly has loaded. The required Wise type
    # is the authoritative success condition for this narrow dependency.
    if (-not ([Management.Automation.PSTypeName]'SabreTools.Wrappers.WiseScript').Type) { throw }
  }
}

function Read-WiseCfbRootStorageClassId {
  <#
  .SYNOPSIS Read an embedded CFB root-storage CLSID.
  .PARAMETER Stream Caller-owned readable and seekable stream; its position is preserved.
  .PARAMETER Offset Offset of the CFB header relative to Stream.
  #>
  [OutputType([guid])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Offset)

  if ($Offset -lt 0 -or $Offset + 512 -gt $Stream.Length) { return $null }
  $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 512
  if ([Convert]::ToHexString($Header, 0, 8) -ne 'D0CF11E0A1B11AE1' -or [BitConverter]::ToUInt16($Header, 0x1C) -ne 0xFFFE) { return $null }
  $SectorShift = [BitConverter]::ToUInt16($Header, 0x1E)
  if ($SectorShift -notin @(9, 12)) { return $null }
  $DirectorySector = [BitConverter]::ToUInt32($Header, 0x30)
  if ($DirectorySector -eq [uint32]::MaxValue) { return $null }
  $RootOffset = $Offset + (([long]$DirectorySector + 1) * (1L -shl $SectorShift))
  if ($RootOffset + 128 -gt $Stream.Length) { return $null }
  $Root = Read-BinaryBytes -Stream $Stream -Offset $RootOffset -Count 128
  if ($Root[0x42] -ne 5) { return $null }
  $Bytes = [byte[]]::new(16)
  [Array]::Copy($Root, 0x50, $Bytes, 0, 16)
  return [guid]::new($Bytes)
}

function Get-WiseSectionMsiRange {
  <#
  .SYNOPSIS Resolve the exact MSI record stored in a PE .WISE section.
  .PARAMETER Stream Caller-owned PE stream.
  .PARAMETER Layout Parsed PE layout for Stream.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Layout)

  $Section = $Layout.Sections | Where-Object { $_.Name -ceq '.WISE' } | Select-Object -First 1
  if (-not $Section -or $Section.RawSize -lt 1024 -or $Section.RawOffset + $Section.RawSize -gt $Stream.Length) { return $null }
  $RecordLength = [long](Read-BinaryInteger -Stream $Stream -Offset ($Section.RawOffset + 24) -Size 4)
  if ($RecordLength -lt 516 -or $RecordLength -gt $Script:WiseMaximumEmbeddedMsiBytes) { return $null }

  $Header = Read-BinaryBytes -Stream $Stream -Offset $Section.RawOffset -Count ([int][Math]::Min([long]$Section.RawSize, 4096L))
  if ([Text.Encoding]::ASCII.GetString($Header).IndexOf('WIS', [StringComparison]::Ordinal) -lt 0) { return $null }
  $SearchLength = [long][Math]::Min([long]$Section.RawSize, 1048576L)
  $MsiOffset = @(Find-BinaryPattern -Stream $Stream -Pattern $Script:WiseCfbMagic -StartOffset $Section.RawOffset -Length $SearchLength -Maximum 8) |
    Where-Object { $ClassId = Read-WiseCfbRootStorageClassId -Stream $Stream -Offset $_; $ClassId -and $ClassId.ToString('B').ToUpperInvariant() -eq $Script:WiseMsiClassId } |
    Select-Object -First 1
  if ($null -eq $MsiOffset) { return $null }

  $MsiLength = $RecordLength - 4
  if ($MsiOffset + $RecordLength -gt $Section.RawOffset + $Section.RawSize -or $MsiOffset + $RecordLength -gt $Stream.Length) { throw 'The .WISE MSI record exceeds its containing section.' }
  $Range = New-BoundedReadStream -Stream $Stream -Offset $MsiOffset -Length $MsiLength -LeaveOpen
  try { $ActualCrc = Get-BinaryCrc32 -Stream $Range -MaximumBytes $MsiLength } finally { $Range.Dispose() }
  $ExpectedCrc = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($MsiOffset + $MsiLength) -Size 4)
  if ($ActualCrc -ne $ExpectedCrc) { throw ('The .WISE MSI CRC32 is invalid: expected {0:X8}, calculated {1:X8}.' -f $ExpectedCrc, $ActualCrc) }
  return [pscustomobject][ordered]@{ Offset = [long]$MsiOffset; Length = [long]$MsiLength; RecordLength = $RecordLength; Crc32 = ('{0:X8}' -f $ExpectedCrc); Section = '.WISE' }
}

function Read-WiseOverlayHeader {
  <#
  .SYNOPSIS Decode the version-dependent WiseScript overlay header.
  .PARAMETER Stream Caller-owned PE stream.
  .PARAMETER Offset Overlay header offset relative to Stream.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Offset)

  if ($Offset -lt 0 -or $Offset + 81 -gt $Stream.Length) { return $null }
  $Range = New-BoundedReadStream -Stream $Stream -Offset $Offset -Length ($Stream.Length - $Offset) -LeaveOpen
  try {
    $DllNameLength = $Range.ReadByte()
    if ($DllNameLength -lt 0 -or $DllNameLength -gt 128) { return $null }
    $DllName = $null
    $DllSize = $null
    if ($DllNameLength -gt 0) {
      $NameBytes = [byte[]]::new($DllNameLength)
      if ($Range.Read($NameBytes, 0, $NameBytes.Length) -ne $NameBytes.Length) { return $null }
      $DllName = [Text.Encoding]::ASCII.GetString($NameBytes)
      $DllSize = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)
    }
    $Flags = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)
    $GraphicsData = Read-BinaryBytes -Stream $Range -Offset $Range.Position -Count 12
    $Range.Position += 12
    $ExitOffset = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)
    $CancelOffset = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)
    $Names = @('WiseScriptInflatedSize', 'WiseScriptDeflatedSize', 'WiseDllDeflatedSize', 'Ctl3d32DeflatedSize', 'SomeData4DeflatedSize', 'RegToolDeflatedSize', 'ProgressDllDeflatedSize', 'SomeData7DeflatedSize', 'SomeData8DeflatedSize', 'SomeData9DeflatedSize', 'SomeData10DeflatedSize', 'FinalFileDeflatedSize', 'FinalFileInflatedSize', 'DeclaredEof')
    $Values = [ordered]@{}
    foreach ($Name in $Names) { $Values[$Name] = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4) }

    # Wise 5 and 6 end the fixed header here. The next DWORD is already raw
    # Deflate data and therefore cannot be a bounded DIB member length.
    $DibDeflatedSize = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)
    if ($DibDeflatedSize -gt $Range.Length -or $DibDeflatedSize -gt $Range.Length - $Range.Position) {
      $Range.Position -= 4
      $Values['DibDeflatedSize'] = 0
      $Values['DibInflatedSize'] = 0
      $InstallScriptDeflatedSize = $null
      $CharacterSet = $null
      $Endianness = 0
      $InitText = ''
    } else {
      $Values['DibDeflatedSize'] = $DibDeflatedSize
      $Values['DibInflatedSize'] = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)

      # Later headers add either endianness directly or an optional source
      # script size and character-set pair before it.
      $InstallScriptDeflatedSize = $null
      $CharacterSet = $null
      $Peek = [uint16](Read-BinaryInteger -Stream $Range -Offset $Range.Position -Size 2)
      if ($Peek -in @(0x0008, 0x0800)) {
        $Endianness = [uint16](Read-BinarySequentialInteger -Stream $Range -Size 2)
      } else {
        $InstallScriptDeflatedSize = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)
        $CharacterSet = [uint32](Read-BinarySequentialInteger -Stream $Range -Size 4)
        $Endianness = [uint16](Read-BinarySequentialInteger -Stream $Range -Size 2)
      }
      if ($Endianness -notin @(0x0008, 0x0800)) { return $null }
      $InitTextLength = $Range.ReadByte()
      if ($InitTextLength -lt 0 -or $Range.Position + $InitTextLength -gt $Range.Length) { return $null }
      $InitTextBytes = [byte[]]::new($InitTextLength)
      if ($InitTextLength -gt 0 -and $Range.Read($InitTextBytes, 0, $InitTextLength) -ne $InitTextLength) { return $null }
      $InitText = [Text.Encoding]::ASCII.GetString($InitTextBytes).TrimEnd([char]0)
    }
    if ($Values.WiseScriptDeflatedSize -lt 5 -or $Values.WiseScriptInflatedSize -lt 1 -or $Values.WiseScriptInflatedSize -gt $Script:WiseMaximumScriptBytes) { return $null }
    if ($Values.WiseScriptDeflatedSize -gt $Range.Length -or $Values.DibDeflatedSize -gt $Range.Length -or $Values.FinalFileDeflatedSize -gt $Range.Length) { return $null }

    return [pscustomobject][ordered]@{
      Offset = $Offset; HeaderLength = [long]$Range.Position; CompressedDataOffset = $Offset + $Range.Position
      DllName = $DllName; DllSize = $DllSize; Flags = $Flags; GraphicsData = $GraphicsData
      WiseScriptExitEventOffset = $ExitOffset; WiseScriptCancelEventOffset = $CancelOffset
      WiseScriptInflatedSize = $Values.WiseScriptInflatedSize; WiseScriptDeflatedSize = $Values.WiseScriptDeflatedSize
      WiseDllDeflatedSize = $Values.WiseDllDeflatedSize; Ctl3d32DeflatedSize = $Values.Ctl3d32DeflatedSize
      SomeData4DeflatedSize = $Values.SomeData4DeflatedSize; RegToolDeflatedSize = $Values.RegToolDeflatedSize
      ProgressDllDeflatedSize = $Values.ProgressDllDeflatedSize; SomeData7DeflatedSize = $Values.SomeData7DeflatedSize
      SomeData8DeflatedSize = $Values.SomeData8DeflatedSize; SomeData9DeflatedSize = $Values.SomeData9DeflatedSize
      SomeData10DeflatedSize = $Values.SomeData10DeflatedSize; FinalFileDeflatedSize = $Values.FinalFileDeflatedSize
      FinalFileInflatedSize = $Values.FinalFileInflatedSize; DeclaredEof = $Values.DeclaredEof
      DibDeflatedSize = $Values.DibDeflatedSize; DibInflatedSize = $Values.DibInflatedSize
      InstallScriptDeflatedSize = $InstallScriptDeflatedSize; CharacterSet = $CharacterSet
      Endianness = ('0x{0:X4}' -f $Endianness); InitText = $InitText
    }
  } catch { return $null } finally { $Range.Dispose() }
}

function Read-WiseDeflateMember {
  <#
  .SYNOPSIS Decode one Wise raw-Deflate member and CRC trailer.
  .PARAMETER Stream Caller-owned Wise container stream.
  .PARAMETER Offset Member offset relative to Stream.
  .PARAMETER CompressedSize Total bytes including the CRC32 trailer.
  .PARAMETER InflatedSize Expected output bytes, or -1 if not published.
  .PARAMETER Capture Return the decompressed bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Offset, [Parameter(Mandatory)][long]$CompressedSize, [long]$InflatedSize = -1, [switch]$Capture, [uint32]$ExpectedCrc32 = 0, [long]$MaximumBytes = $Script:WiseMaximumScriptBytes)

  if ($CompressedSize -lt 5 -or $Offset -lt 0 -or $CompressedSize -gt $Stream.Length - $Offset) { throw 'The Wise Deflate member is outside the containing stream.' }
  if ($InflatedSize -gt $MaximumBytes) { throw "The Wise Deflate member exceeds the $MaximumBytes-byte output limit." }
  $Compressed = New-BoundedReadStream -Stream $Stream -Offset $Offset -Length ($CompressedSize - 4) -LeaveOpen
  # Checksum every header member, including ones whose bytes are discarded.
  # Otherwise a repurposed size slot can consume a prefix of the next member.
  $Destination = [IO.MemoryStream]::new()
  try {
    $Arguments = @{ Algorithm = 'Deflate'; Stream = $Compressed; Destination = $Destination; MaximumBytes = $MaximumBytes }
    if ($InflatedSize -ge 0) { $Arguments.UncompressedSize = $InflatedSize }
    $Written = Expand-InstallerCompressedStream @Arguments
    $Destination.Position = 0
    $ActualCrc = Get-BinaryCrc32 -Stream $Destination -MaximumBytes $Written
    $Bytes = $Capture ? $Destination.ToArray() : $null
  } finally {
    $Destination.Dispose()
    $Compressed.Dispose()
  }
  $StoredCrc = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + $CompressedSize - 4) -Size 4)
  if ($ActualCrc -ne $StoredCrc -or ($ExpectedCrc32 -ne 0 -and $ActualCrc -ne $ExpectedCrc32)) { throw ('The Wise Deflate member CRC32 is invalid: trailer {0:X8}, catalog {1:X8}, calculated {2:X8}.' -f $StoredCrc, $ExpectedCrc32, $ActualCrc) }
  return [pscustomobject]@{ Offset = $Offset; CompressedSize = $CompressedSize; InflatedSize = [long]$Written; Crc32 = ('{0:X8}' -f $StoredCrc); Bytes = $Bytes }
}

function ConvertFrom-WiseInstallScriptSource {
  <#
  .SYNOPSIS Read deterministic project metadata from an embedded WSE listing.
  .PARAMETER Bytes Decompressed INSTALL_SCRIPT bytes.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][byte[]]$Bytes)

  if (-not $Bytes) { return $null }
  $Text = [Text.Encoding]::GetEncoding(1252).GetString($Bytes).TrimEnd([char]0)
  if (-not $Text.StartsWith('Document Type: WSE', [StringComparison]::Ordinal)) { return $null }
  $GlobalMatch = [regex]::Match($Text, '(?ms)^item: Global\r?\n(?<body>.*?)^end\s*$')
  if (-not $GlobalMatch.Success) { return [pscustomobject]@{ IsWse = $true; TextLength = $Text.Length } }
  $Properties = [ordered]@{}
  foreach ($Match in [regex]::Matches($GlobalMatch.Groups['body'].Value, '(?m)^  (?<name>[^=\r\n]+)=(?<value>.*)$')) { $Properties[$Match.Groups['name'].Value] = $Match.Groups['value'].Value.TrimEnd() }
  $Variables = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $Properties.GetEnumerator()) {
    if ($Entry.Key -match '^Variable Name(?<index>\d+)$') {
      $DefaultKey = "Variable Default$($Matches.index)"
      $Variables[[string]$Entry.Value] = $Properties.Contains($DefaultKey) ? [string]$Properties[$DefaultKey] : ''
    }
  }
  return [pscustomobject][ordered]@{ IsWse = $true; TextLength = $Text.Length; Version = $Properties['Version']; Title = $Properties['Title']; RequestedExecutionLevel = $Properties['Requested Execution Level']; Variables = $Variables }
}

function ConvertFrom-WiseScriptModel {
  <#
  .SYNOPSIS Project a WiseScript state machine into bounded installer evidence.
  .PARAMETER Bytes Decompressed WiseScript bytes.
  .PARAMETER SourceMetadata Optional WSE global metadata and variables.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, $SourceMetadata)

  Import-WiseScriptReader
  $Memory = [IO.MemoryStream]::new($Bytes, $false)
  try { $Wrapper = [SabreTools.Wrappers.WiseScript]::Create($Memory) } finally { $Memory.Dispose() }
  if (-not $Wrapper -or -not $Wrapper.Model -or $Wrapper.Model.States.Count -eq 0) { throw 'The decompressed WiseScript state machine is malformed or unsupported.' }

  $Variables = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  if ($SourceMetadata -and $SourceMetadata.Variables) { foreach ($Pair in $SourceMetadata.Variables.GetEnumerator()) { $Variables[$Pair.Key] = [string]$Pair.Value } }
  $Files = [Collections.Generic.List[object]]::new()
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $Executions = [Collections.Generic.List[object]]::new()
  $ExternalCalls = [Collections.Generic.List[object]]::new()
  $OperationCounts = [ordered]@{}

  foreach ($State in $Wrapper.Model.States) {
    $Operation = [string]$State.Op
    $OperationCounts[$Operation] = $OperationCounts.Contains($Operation) ? ([int]$OperationCounts[$Operation] + 1) : 1
    $Data = $State.Data
    switch ($Operation) {
      'CallDllFunction' {
        # SabreTools names compiler-generated Set Variable records f16. Other
        # records represent real DLL calls and remain opaque system effects.
        if ($Data.FunctionName -ceq 'f16' -and [string]::IsNullOrEmpty([string]$Data.DllPath)) {
          foreach ($Entry in @($Data.Entries)) { if (-not [string]::IsNullOrWhiteSpace([string]$Entry.Variable)) { $Variables[[string]$Entry.Variable] = [string]$Entry.Value } }
        } else {
          $ExternalCalls.Add([pscustomobject]@{ DllPath = [string]$Data.DllPath; FunctionName = [string]$Data.FunctionName; ReturnVariable = [string]$Data.ReturnVariable })
        }
      }
      'InstallFile' {
        $Files.Add([pscustomobject][ordered]@{ Index = $Files.Count + 1; Flags = [uint16]$Data.Flags; DeflateStart = [long]$Data.DeflateStart; DeflateEnd = [long]$Data.DeflateEnd; CompressedSize = [long]$Data.DeflateEnd - [long]$Data.DeflateStart; InflatedSize = [long]$Data.InflatedSize; Crc32 = [uint32]$Data.Crc32; DestinationPathname = [string]$Data.DestinationPathname })
      }
      'EditRegistry' { $RegistryWrites.Add([pscustomobject]@{ FlagsAndRoot = [uint16]$Data.FlagsAndRoot; DataType = [byte]$Data.DataType; Key = [string]$Data.Key; ValueName = [string]$Data.ValueName; Value = [string]$Data.NewValue }) }
      'ExecuteProgram' { $Executions.Add([pscustomobject]@{ Flags = [uint16]$Data.Flags; Path = [string]$Data.Pathname; Arguments = [string]$Data.CommandLine; WorkingDirectory = [string]$Data.DefaultDirectory }) }
    }
  }

  return [pscustomobject][ordered]@{
    Header = [pscustomobject]@{ Flags = $Wrapper.Model.Header.Flags; LogPathname = $Wrapper.Model.Header.LogPathname; MessageFont = $Wrapper.Model.Header.MessageFont; LanguageCount = $Wrapper.Model.Header.LanguageCount; Strings = @($Wrapper.Model.Header.HeaderStrings) }
    Variables = $Variables; Files = @($Files); RegistryWrites = @($RegistryWrites); Executions = @($Executions); ExternalCalls = @($ExternalCalls); OperationCounts = $OperationCounts
  }
}

function Resolve-WiseVariableText {
  <#
  .SYNOPSIS Expand deterministic Wise %VARIABLE% references.
  .PARAMETER Value Text containing Wise references.
  .PARAMETER Variables Case-insensitive variable-value map.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Value, [Parameter(Mandatory)][Collections.Generic.IDictionary[string, string]]$Variables)

  if ($null -eq $Value) { return $null }
  $Resolved = $Value
  for ($Depth = 0; $Depth -lt 16; $Depth++) {
    $Changed = $false
    $VariableMatches = [regex]::Matches($Resolved, '%(?<name>[^%]+)%')
    foreach ($Match in @($VariableMatches)) {
      $Name = $Match.Groups['name'].Value
      if ($Variables.ContainsKey($Name) -and $Variables[$Name].IndexOf($Match.Value, [StringComparison]::OrdinalIgnoreCase) -lt 0) { $Resolved = $Resolved.Replace($Match.Value, $Variables[$Name]); $Changed = $true }
    }
    if (-not $Changed) { break }
  }
  return $Resolved
}

function Get-WiseScriptArpEvidence {
  <#
  .SYNOPSIS Reconstruct literal uninstall rows from WiseScript registry actions.
  .PARAMETER Script Parsed WiseScript model containing variables and registry writes.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()]$Script)

  if (-not $Script) { return [pscustomobject]@{ Entries = @(); Unique = $null } }
  $Writes = [Collections.Generic.List[object]]::new()
  foreach ($Write in @($Script.RegistryWrites)) {
    # The low five bits select the Wise registry root. Only HKCU (1) and HKLM
    # (2) can directly own a conventional per-user or per-machine ARP row.
    $Root = [int]$Write.FlagsAndRoot -band 0x1F
    if ($Root -notin @(1, 2) -or ([int]$Write.FlagsAndRoot -band 0x40) -ne 0) { continue }
    $Key = Resolve-WiseVariableText -Value $Write.Key -Variables $Script.Variables
    if ($Key -notmatch '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<code>.+)$' -or $Key.Contains('%')) { continue }
    $ValueName = Resolve-WiseVariableText -Value $Write.ValueName -Variables $Script.Variables
    $Value = Resolve-WiseVariableText -Value $Write.Value -Variables $Script.Variables
    $Writes.Add([pscustomobject]@{ Identity = "$Root|$Key"; Root = $Root; Key = $Key; ProductCode = $Matches.code; ValueName = $ValueName; Value = $Value; DataType = $Write.DataType })
  }

  $Entries = [Collections.Generic.List[object]]::new()
  foreach ($Group in @($Writes | Group-Object Identity)) {
    $Values = [ordered]@{}
    foreach ($Write in @($Group.Group)) {
      if ([string]::IsNullOrWhiteSpace([string]$Write.ValueName)) { continue }
      $Values[[string]$Write.ValueName] = [string]$Write.Value
    }
    $First = $Group.Group[0]
    $Entries.Add([pscustomobject][ordered]@{
      ProductCode = [string]$First.ProductCode
      Scope = $First.Root -eq 1 ? 'user' : 'machine'
      RegistryHive = $First.Root -eq 1 ? 'HKCU' : 'HKLM'
      RegistryPath = [string]$First.Key
      DisplayName = $Values['DisplayName']
      DisplayVersion = $Values['DisplayVersion']
      Publisher = $Values['Publisher']
      InstallLocation = $Values['InstallLocation']
      UninstallString = $Values['UninstallString']
      QuietUninstallString = $Values['QuietUninstallString']
      DisplayIcon = $Values['DisplayIcon']
      SystemComponent = $Values['SystemComponent']
      Values = $Values
    })
  }
  return [pscustomobject]@{ Entries = @($Entries); Unique = $Entries.Count -eq 1 ? $Entries[0] : $null }
}

function Get-WiseScriptContext {
  <#
  .SYNOPSIS Parse a WiseScript PE overlay and state-machine catalog once.
  .PARAMETER Stream Caller-owned PE stream or nested-PE view.
  .PARAMETER Layout Parsed PE layout for Stream.
  .PARAMETER OverlayOffset Explicit overlay-header offset for an NE container.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, $Layout, [long]$OverlayOffset = -1)

  if ($OverlayOffset -lt 0) {
    if (-not $Layout) { return $null }
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
  }
  $Header = Read-WiseOverlayHeader -Stream $Stream -Offset $OverlayOffset
  if (-not $Header) { return $null }
  $CurrentOffset = $Header.CompressedDataOffset
  $Members = [Collections.Generic.List[object]]::new()
  $SkippedMembers = [Collections.Generic.List[string]]::new()
  $WiseScriptBytes = $null
  $InstallScriptBytes = $null
  $Definitions = @(
    @{ Name = 'WiseColors.dib'; Size = $Header.DibDeflatedSize; Inflated = $Header.DibInflatedSize; Capture = $false }
    @{ Name = 'WiseScript.bin'; Size = $Header.WiseScriptDeflatedSize; Inflated = $Header.WiseScriptInflatedSize; Capture = $true; Required = $true }
    @{ Name = 'WISE0001.DLL'; Size = $Header.WiseDllDeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'CTL3D32.DLL'; Size = $Header.Ctl3d32DeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'FILE0004'; Size = $Header.SomeData4DeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'Ocxreg32.EXE'; Size = $Header.RegToolDeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'PROGRESS.DLL'; Size = $Header.ProgressDllDeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'FILE0007'; Size = $Header.SomeData7DeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'FILE0008'; Size = $Header.SomeData8DeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'FILE0009'; Size = $Header.SomeData9DeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'FILE000A'; Size = $Header.SomeData10DeflatedSize; Inflated = -1; Capture = $false }
    @{ Name = 'INSTALL_SCRIPT'; Size = $Header.InstallScriptDeflatedSize; Inflated = -1; Capture = $true }
    @{ Name = 'FILE00XX.DAT'; Size = $Header.FinalFileDeflatedSize; Inflated = $Header.FinalFileInflatedSize; Capture = $false }
  )
  foreach ($Definition in $Definitions) {
    $Size = [long]$Definition.Size
    if ($Size -eq 0) { continue }
    try {
      $Member = Read-WiseDeflateMember -Stream $Stream -Offset $CurrentOffset -CompressedSize $Size -InflatedSize ([long]$Definition.Inflated) -Capture:([bool]$Definition.Capture) -MaximumBytes $Script:WiseMaximumScriptBytes
      $Members.Add([pscustomobject]@{ Name = $Definition.Name; Offset = $Member.Offset; CompressedSize = $Member.CompressedSize; InflatedSize = $Member.InflatedSize; Crc32 = $Member.Crc32 })
      if ($Definition.Name -ceq 'WiseScript.bin') { $WiseScriptBytes = $Member.Bytes }
      if ($Definition.Name -ceq 'INSTALL_SCRIPT') { $InstallScriptBytes = $Member.Bytes }
      $CurrentOffset += $Size
    } catch {
      if ($Definition.Required) { throw "The required WiseScript member could not be decoded: $($_.Exception.Message)" }
      # Some Wise 9 prerequisite wrappers repurpose unused size slots. A slot
      # that does not decode at the current position is evidence, not a member.
      $SkippedMembers.Add("$($Definition.Name): $($_.Exception.Message)")
    }
  }
  if (-not $WiseScriptBytes) { throw 'The Wise overlay does not contain a usable WiseScript state machine.' }
  $SourceMetadata = ConvertFrom-WiseInstallScriptSource -Bytes $InstallScriptBytes
  $Script = $null
  $ScriptModelError = $null
  try {
    $Script = ConvertFrom-WiseScriptModel -Bytes $WiseScriptBytes -SourceMetadata $SourceMetadata
    foreach ($File in $Script.Files) { $File | Add-Member -NotePropertyName ResolvedDestinationPath -NotePropertyValue (Resolve-WiseVariableText -Value $File.DestinationPathname -Variables $Script.Variables) }
  } catch {
    # A structurally valid header and checksummed script member still prove the
    # Wise family when a historical state-machine generation is unsupported.
    $ScriptModelError = $_.Exception.Message
  }
  return [pscustomobject][ordered]@{ Layout = $Layout; OverlayHeader = $Header; HeaderMembers = @($Members); SkippedHeaderMembers = @($SkippedMembers); PayloadDataOffset = [long]$CurrentOffset; Script = $Script; ScriptModelError = $ScriptModelError; InstallScriptMetadata = $SourceMetadata }
}

function Get-WiseStructuralContext {
  <#
  .SYNOPSIS Identify the physical Wise route and parse its catalog.
  .PARAMETER Stream Caller-owned complete installer stream.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  $OuterLayout = Get-PELayout -Stream $Stream
  if (-not $OuterLayout) {
    # Wise 5 through early 7 can use a 16-bit New Executable launcher. Let the
    # bounded NE reader locate its overlay, then apply Dumplings' normal Wise
    # header, Deflate, CRC, and state-machine validation to prove the family.
    if ($Stream.Length -ge 64 -and [uint16](Read-BinaryInteger -Stream $Stream -Offset 0 -Size 2) -eq 0x5A4D) {
      $NewHeaderOffset = [long](Read-BinaryInteger -Stream $Stream -Offset 60 -Size 4)
      if ($NewHeaderOffset -ge 64 -and $NewHeaderOffset + 2 -le $Stream.Length -and [uint16](Read-BinaryInteger -Stream $Stream -Offset $NewHeaderOffset -Size 2) -eq 0x454E) {
        Import-WiseScriptReader
        $Stream.Position = 0
        $NewExecutable = [SabreTools.Wrappers.NewExecutable]::Create($Stream)
        $OverlayOffset = $NewExecutable ? [long]$NewExecutable.FindWiseOverlayHeader() : -1L
        if ($OverlayOffset -ge 0) {
          $ScriptContext = Get-WiseScriptContext -Stream $Stream -OverlayOffset $OverlayOffset
          if ($ScriptContext) { return [pscustomobject]@{ Route = 'NewExecutable/WiseScript'; ContainerOffset = 0L; ContainerLength = $Stream.Length; OuterLayout = $null; ScriptContext = $ScriptContext; MsiRange = $null } }
        }
      }
    }
    throw 'The file does not contain a supported PE or NE Wise installer route.'
  }
  $DirectMsi = Get-WiseSectionMsiRange -Stream $Stream -Layout $OuterLayout
  if ($DirectMsi) { return [pscustomobject]@{ Route = 'WiseSection/Msi'; ContainerOffset = 0L; ContainerLength = $Stream.Length; OuterLayout = $OuterLayout; ScriptContext = $null; MsiRange = $DirectMsi } }
  $DirectScript = Get-WiseScriptContext -Stream $Stream -Layout $OuterLayout
  if ($DirectScript) { return [pscustomobject]@{ Route = 'WiseScript/Overlay'; ContainerOffset = 0L; ContainerLength = $Stream.Length; OuterLayout = $OuterLayout; ScriptContext = $DirectScript; MsiRange = $null } }

  # Vendor launchers can append a complete Wise prerequisite setup as slack in
  # .rsrc. Each MZ candidate must be a PE with a decodable WiseScript overlay.
  $Resource = $OuterLayout.Sections | Where-Object { $_.Name -ceq '.rsrc' } | Select-Object -First 1
  if ($Resource) {
    $Certificate = $OuterLayout.DataDirectories.Certificate
    $LogicalEnd = if ($Certificate -and $Certificate.Rva -gt 0 -and $Certificate.Rva -le $Stream.Length) { [long]$Certificate.Rva } else { $Stream.Length }
    $SearchLength = [long][Math]::Min([long]$Resource.RawSize, $LogicalEnd - [long]$Resource.RawOffset)
    if ($SearchLength -gt 0) {
      foreach ($CandidateOffset in @(Find-BinaryPattern -Stream $Stream -Pattern ([byte[]](0x4D, 0x5A)) -StartOffset $Resource.RawOffset -Length $SearchLength -Maximum 64)) {
        if ($CandidateOffset + 512 -gt $LogicalEnd) { continue }
        $Nested = New-BoundedReadStream -Stream $Stream -Offset $CandidateOffset -Length ($LogicalEnd - $CandidateOffset) -LeaveOpen
        try {
          $NestedLayout = Get-PELayout -Stream $Nested
          if (-not $NestedLayout) { continue }
          $NestedScript = Get-WiseScriptContext -Stream $Nested -Layout $NestedLayout
          if ($NestedScript) { return [pscustomobject]@{ Route = 'ResourceLauncher/WiseScript'; ContainerOffset = [long]$CandidateOffset; ContainerLength = [long]($LogicalEnd - $CandidateOffset); OuterLayout = $OuterLayout; ScriptContext = $NestedScript; MsiRange = $null } }
        } catch { continue } finally { $Nested.Dispose() }
      }
    }
  }
  throw 'The PE does not contain a supported WiseScript overlay or validated .WISE MSI record.'
}

function Export-WisePayloadRecord {
  <#
  .SYNOPSIS Extract and verify one WiseScript InstallFile record.
  .PARAMETER Stream Caller-owned complete installer stream.
  .PARAMETER Context Structural context containing container and payload bases.
  .PARAMETER Record Projected WiseScript InstallFile record.
  .PARAMETER DestinationPath Exact output path.
  #>
  [OutputType([IO.FileInfo])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$DestinationPath)

  if ($Record.CompressedSize -lt 5 -or $Record.InflatedSize -lt 1 -or $Record.InflatedSize -gt $Script:WiseMaximumPayloadBytes) { throw 'The WiseScript payload record has invalid or excessive sizes.' }
  if ($Context.ScriptContext.PayloadDataOffset + $Record.DeflateEnd -gt $Context.ContainerLength) { throw 'The WiseScript payload record exceeds its containing PE.' }
  $AbsoluteOffset = $Context.ContainerOffset + $Context.ScriptContext.PayloadDataOffset + $Record.DeflateStart
  $ResolvedDestination = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $Parent = [IO.Path]::GetDirectoryName($ResolvedDestination)
  if ($Parent) { $null = New-Item -ItemType Directory -Path $Parent -Force }
  $Compressed = New-BoundedReadStream -Stream $Stream -Offset $AbsoluteOffset -Length ($Record.CompressedSize - 4) -LeaveOpen
  $Output = [IO.File]::Open($ResolvedDestination, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Deflate -Stream $Compressed -Destination $Output -MaximumBytes $Script:WiseMaximumPayloadBytes -UncompressedSize $Record.InflatedSize
    $Output.Flush()
    $Output.Position = 0
    $ActualCrc = Get-BinaryCrc32 -Stream $Output -MaximumBytes $Record.InflatedSize
  } catch {
    Remove-Item -LiteralPath $ResolvedDestination -Force -ErrorAction SilentlyContinue
    throw
  } finally {
    $Output.Dispose()
    $Compressed.Dispose()
  }
  $StoredCrc = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($AbsoluteOffset + $Record.CompressedSize - 4) -Size 4)
  if ($StoredCrc -ne $ActualCrc -or ($Record.Crc32 -ne 0 -and $Record.Crc32 -ne $ActualCrc)) {
    Remove-Item -LiteralPath $ResolvedDestination -Force -ErrorAction SilentlyContinue
    throw ('The WiseScript payload CRC32 is invalid for record {0}: trailer {1:X8}, catalog {2:X8}, calculated {3:X8}.' -f $Record.Index, $StoredCrc, [uint32]$Record.Crc32, $ActualCrc)
  }
  return Get-Item -LiteralPath $ResolvedDestination -Force
}

function Get-WiseNestedMsiEvidence {
  <#
  .SYNOPSIS Select a WiseScript payload that structurally owns a .WISE MSI record.
  .PARAMETER Stream Caller-owned complete installer stream.
  .PARAMETER Context Parsed WiseScript context.
  .PARAMETER TemporaryFolder Caller-owned scratch directory.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$TemporaryFolder)

  if (-not $Context.ScriptContext.Script) { return $null }
  $CandidateCount = 0
  foreach ($Record in $Context.ScriptContext.Script.Files) {
    if ([IO.Path]::GetExtension([string]$Record.ResolvedDestinationPath) -ine '.exe') { continue }
    if (++$CandidateCount -gt 16) { break }
    $CandidatePath = Join-Path $TemporaryFolder ("candidate-{0:D2}.exe" -f $Record.Index)
    try {
      $null = Export-WisePayloadRecord -Stream $Stream -Context $Context -Record $Record -DestinationPath $CandidatePath
      $CandidateStream = [IO.File]::Open($CandidatePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        $Layout = Get-PELayout -Stream $CandidateStream
        if (-not $Layout) { continue }
        $Range = Get-WiseSectionMsiRange -Stream $CandidateStream -Layout $Layout
        if (-not $Range) { continue }
        $MsiPath = Join-Path $TemporaryFolder 'embedded.msi'
        $Destination = [IO.File]::Open($MsiPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BinaryStreamRange -Source $CandidateStream -Destination $Destination -Offset $Range.Offset -Length $Range.Length } finally { $Destination.Dispose() }
        return [pscustomobject]@{ MsiPath = $MsiPath; Range = $Range; PayloadRecord = $Record; LauncherPath = $CandidatePath }
      } finally { $CandidateStream.Dispose() }
    } catch { continue }
  }
  return $null
}

function Get-WiseInfo {
  <#
  .SYNOPSIS Read Wise container, script, nested MSI, and ARP evidence.
  .PARAMETER Path Path to a Wise installer; it is never executed.
  .OUTPUTS Common parser fields plus route, script, payload, registry, and execution evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force -ErrorAction Stop
    $TemporaryFolder = New-TempFolder
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Context = Get-WiseStructuralContext -Stream $Stream
      $MsiEvidence = $null
      if ($Context.MsiRange) {
        $MsiPath = Join-Path $TemporaryFolder 'embedded.msi'
        $Destination = [IO.File]::Open($MsiPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BinaryStreamRange -Source $Stream -Destination $Destination -Offset $Context.MsiRange.Offset -Length $Context.MsiRange.Length } finally { $Destination.Dispose() }
        $MsiEvidence = [pscustomobject]@{ MsiPath = $MsiPath; Range = $Context.MsiRange; PayloadRecord = $null; LauncherPath = $File.FullName }
      } elseif ($Context.ScriptContext) {
        $MsiEvidence = Get-WiseNestedMsiEvidence -Stream $Stream -Context $Context -TemporaryFolder $TemporaryFolder
      }
      $MsiInfo = $MsiEvidence ? (Get-MsiInstallerInfo -Path $MsiEvidence.MsiPath) : $null
      $ScriptContext = $Context.ScriptContext
      $ScriptModel = $ScriptContext ? $ScriptContext.Script : $null
      $ArpEvidence = Get-WiseScriptArpEvidence -Script $ScriptModel
      $ScriptArp = $ArpEvidence.Unique
      $SourceMetadata = $ScriptContext ? $ScriptContext.InstallScriptMetadata : $null
      $VersionStrings = @(Get-PEVersionStringTable -Path $File.FullName)[0]
      $RequestedExecutionLevel = $SourceMetadata ? [string]$SourceMetadata.RequestedExecutionLevel : $null
      $ElevationRequirement = $RequestedExecutionLevel -ceq 'requireAdministrator' ? 'elevationRequired' : $null
      $Publisher = $MsiInfo ? $MsiInfo.Publisher : $null
      if ([string]::IsNullOrWhiteSpace([string]$Publisher)) { $Publisher = $VersionStrings ? $VersionStrings.CompanyName : $null }
      $DisplayName = $MsiInfo ? $MsiInfo.DisplayName : $null
      if ([string]::IsNullOrWhiteSpace([string]$DisplayName)) { $DisplayName = $SourceMetadata ? $SourceMetadata.Title : $null }
      $DisplayVersion = $MsiInfo ? $MsiInfo.DisplayVersion : $null
      if ([string]::IsNullOrWhiteSpace([string]$DisplayVersion)) { $DisplayVersion = $SourceMetadata ? $SourceMetadata.Version : $null }
      $Scope = $MsiInfo ? $MsiInfo.Scope : $null
      if (-not $Scope -and $MsiEvidence) {
        $AllUsers = try { Read-MsiProperty -Path $MsiEvidence.MsiPath -Query "SELECT `Value` FROM `Property` WHERE `Property`='ALLUSERS'" } catch { $null }
        if ($AllUsers -eq '1') { $Scope = 'machine' }
      }

      $IsNestedMsiWrapper = [bool]($Context.ScriptContext -and $MsiInfo)
      $IsDirectMsiWrapper = $Context.Route -ceq 'WiseSection/Msi'
      [string[]]$InstallModes = if ($IsNestedMsiWrapper) { @('interactive') } elseif ($IsDirectMsiWrapper) { @('interactive', 'silent', 'silentWithProgress') } else { @('interactive', 'silent') }
      $InstallerSwitches = if ($IsNestedMsiWrapper) {
        [ordered]@{}
      } elseif ($IsDirectMsiWrapper) {
        $DirectSwitches = [ordered]@{ Silent = '/quiet /norestart'; SilentWithProgress = '/passive /norestart'; Log = '/log "<LOGPATH>"' }
        if (-not [string]::IsNullOrWhiteSpace([string]$MsiInfo.InstallLocationProperty)) { $DirectSwitches['InstallLocation'] = "$($MsiInfo.InstallLocationProperty)=`"<INSTALLPATH>`"" }
        $DirectSwitches
      } else {
        [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
      }

      $Diagnostics = [Collections.Generic.List[object]]::new()
      if ($MsiInfo) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Metadata.NestedMsiAuthority' -Source 'Wise' -Message 'The validated nested MSI is authoritative for ProductCode, UpgradeCode, associations, and visible Windows Installer ARP behavior.' -Kind Information -Areas Metadata -AffectedFields @('ProductCode', 'UpgradeCode', 'AppsAndFeaturesEntries'))) }
      if ($IsNestedMsiWrapper) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Installability.NestedMsiInteractiveOnly' -Source 'Wise' -Message 'The WiseScript prerequisite wrapper forwards its command line but does not map /S to quiet nested-MSI UI; this route is treated as interactive-only.' -Kind Unsupported -Areas Installability -AffectedFields @('InstallModes', 'InstallerSwitches'))) }
      if ($MsiInfo -and -not $Scope) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Metadata.ScopeUnresolved' -Source 'Wise' -Message 'The nested MSI does not explicitly prove a single installation scope. Preserve or omit Scope until VM evidence establishes it.' -Kind Incomplete -Areas Metadata -AffectedFields Scope)) }
      foreach ($Skipped in @($ScriptContext ? $ScriptContext.SkippedHeaderMembers : @())) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Extraction.HeaderSlotNotPhysical' -Source 'Wise' -Message "A Wise overlay size slot did not describe a physical Deflate member and was not used to advance the payload base: $Skipped" -Kind Fallback -Areas Extraction -Evidence $Skipped)) }
      if ($ScriptContext -and $ScriptContext.ScriptModelError) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Metadata.ScriptModelUnsupported' -Source 'Wise' -Message "The WiseScript member is structurally valid, but its historical state-machine layout is not yet decoded: $($ScriptContext.ScriptModelError)" -Kind Unsupported -Areas Metadata, Extraction -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries'))) }
      if ($ScriptModel -and @($ScriptModel.ExternalCalls).Count -gt 0) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Metadata.ExternalDllEffectsOpaque' -Source 'Wise' -Message 'The WiseScript state machine calls external DLL functions whose system effects require static inspection or VM validation.' -Kind ManualValidation -Areas Metadata, Security)) }
      if (@($ArpEvidence.Entries).Count -gt 1) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Metadata.MultipleArpEntries' -Source 'Wise' -Message 'The WiseScript contains multiple literal uninstall-key identities. They are returned as evidence, but no scalar ProductCode or scope is selected without condition or VM evidence.' -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'AppsAndFeaturesEntries') -Evidence @($ArpEvidence.Entries))) }
      if ($ScriptArp) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Wise.Metadata.ScriptArpConditionsRequireValidation' -Source 'Wise' -Message 'A single literal WiseScript uninstall row was reconstructed and returned as candidate evidence. The current state projection does not prove surrounding branch conditions, so it is not promoted to manifest identity without VM validation.' -Kind ManualValidation -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'AppsAndFeaturesEntries') -Evidence $ScriptArp)) }

      $Variant = if ($IsNestedMsiWrapper) { 'WiseScript MSI prerequisite wrapper' } elseif ($IsDirectMsiWrapper) { 'Wise for Windows Installer' } else { 'WiseScript' }
      $FormatProfile = if ($IsDirectMsiWrapper) { 'WiseSectionMsi' } elseif ($ScriptContext.OverlayHeader.DibDeflatedSize -eq 0 -and $ScriptContext.OverlayHeader.Endianness -ceq '0x0000') { 'LegacyOverlay' } elseif ($ScriptContext.OverlayHeader.InstallScriptDeflatedSize) { 'SourceOverlay' } else { 'ExtendedOverlay' }
      $BuilderVersion = $SourceMetadata ? [string]$SourceMetadata.Version : $null
      if ([string]::IsNullOrWhiteSpace($BuilderVersion) -and $ScriptModel) {
        foreach ($HeaderString in @($ScriptModel.Header.Strings)) {
          $Match = [regex]::Match([string]$HeaderString, '(?i)Wise Installer\s+(?<version>\d+(?:\.\d+)+)')
          if ($Match.Success) { $BuilderVersion = $Match.Groups['version'].Value; break }
        }
      }
      $UnresolvedFields = [Collections.Generic.List[string]]::new()
      if (-not $MsiInfo) { $UnresolvedFields.Add('ProductCode'); $UnresolvedFields.Add('AppsAndFeaturesEntries') }
      if ($MsiInfo -and -not $Scope) { $UnresolvedFields.Add('Scope') }

      $ProductCode = $MsiInfo ? $MsiInfo.ProductCode : $null
      $UpgradeCode = $MsiInfo ? $MsiInfo.UpgradeCode : $null
      $DefaultInstallLocation = $MsiInfo ? $MsiInfo.DefaultInstallLocation : $null
      $AppsAndFeaturesProductCode = $MsiInfo ? $MsiInfo.AppsAndFeaturesProductCode : $null
      $AppsAndFeaturesInstallerType = $MsiInfo ? $MsiInfo.AppsAndFeaturesInstallerType : $null
      $InstallLocationProperty = $MsiInfo ? $MsiInfo.InstallLocationProperty : $null
      $InstallLocationSwitch = $MsiInfo ? $MsiInfo.InstallLocationSwitch : $null
      $NestedInstallerBuilder = $MsiInfo ? $MsiInfo.InstallerBuilder : $null
      $AppsAndFeaturesEntries = $MsiInfo ? @($MsiInfo.AppsAndFeaturesEntries) : @()
      $RegistryAssociationInfo = $MsiInfo ? $MsiInfo.RegistryAssociationInfo : $null
      $Protocols = $MsiInfo ? @($MsiInfo.Protocols) : @()
      $FileExtensions = $MsiInfo ? @($MsiInfo.FileExtensions) : @()
      $SupportedArchitectures = $MsiInfo ? @($MsiInfo.SupportedArchitectures) : @()
      $UnsupportedArchitectures = $MsiInfo ? @($MsiInfo.UnsupportedArchitectures) : @()
      $OverlayHeader = $ScriptContext ? $ScriptContext.OverlayHeader : $null
      $HeaderMembers = $ScriptContext ? @($ScriptContext.HeaderMembers) : @()
      $PayloadCatalog = $ScriptModel ? @($ScriptModel.Files) : @()
      $RegistryWrites = $ScriptModel ? @($ScriptModel.RegistryWrites) : @()
      $ExecutedPrograms = $ScriptModel ? @($ScriptModel.Executions) : @()
      $OperationCounts = $ScriptModel ? $ScriptModel.OperationCounts : $null
      $EmbeddedMsi = $MsiEvidence ? $MsiEvidence.Range : $null
      $EmbeddedMsiPayloadRecord = $MsiEvidence ? $MsiEvidence.PayloadRecord : $null
      $MsiUninstallString = $null
      $MsiQuietUninstallString = $null
      $MsiDisplayIcon = $null
      if ($MsiInfo) {
        $Property = $MsiInfo.PSObject.Properties['UninstallString']; if ($Property) { $MsiUninstallString = $Property.Value }
        $Property = $MsiInfo.PSObject.Properties['QuietUninstallString']; if ($Property) { $MsiQuietUninstallString = $Property.Value }
        $Property = $MsiInfo.PSObject.Properties['DisplayIcon']; if ($Property) { $MsiDisplayIcon = $Property.Value }
      }

      [pscustomobject][ordered]@{
        Path = $File.FullName; InstallerType = 'exe'; ProductCode = $ProductCode; UpgradeCode = $UpgradeCode
        DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher; Scope = $Scope
        DefaultInstallLocation = $DefaultInstallLocation; WritesAppsAndFeaturesEntry = $MsiInfo ? $true : $null
        AppsAndFeaturesProductCode = $AppsAndFeaturesProductCode; AppsAndFeaturesInstallerType = $AppsAndFeaturesInstallerType
        Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic @($Diagnostics)); UnresolvedFields = [string[]]@($UnresolvedFields | Sort-Object -Unique)
        Family = 'Wise'; WiseVariant = $Variant; FormatProfile = $FormatProfile; BuilderVersion = $BuilderVersion; ContainerRoute = $Context.Route
        StructuralRoutes = @([pscustomobject]@{ RouteId = $Context.Route; Layer = 'Container'; SupportStatus = 'Supported'; Evidence = $Variant }; if ($MsiInfo) { [pscustomobject]@{ RouteId = 'WiseSection/Msi'; Layer = 'NestedPayload'; SupportStatus = 'Supported'; Evidence = $MsiEvidence.Range } })
        SupportedScopes = $Scope ? @($Scope) : @(); InstallModes = $InstallModes; InstallerSwitches = $InstallerSwitches; InstallerSuccessCodes = @()
        ElevationRequirement = $ElevationRequirement; RequestedExecutionLevel = $RequestedExecutionLevel
        InstallLocationProperty = $InstallLocationProperty; InstallLocationSwitch = $InstallLocationSwitch
        NestedInstallerBuilder = $NestedInstallerBuilder; AppsAndFeaturesEntries = $AppsAndFeaturesEntries
        RegistryAssociationInfo = $RegistryAssociationInfo; Protocols = $Protocols; FileExtensions = $FileExtensions
        SupportedArchitectures = $SupportedArchitectures; UnsupportedArchitectures = $UnsupportedArchitectures
        OverlayHeader = $OverlayHeader; HeaderMembers = $HeaderMembers
        PayloadCatalog = $PayloadCatalog; RegistryWrites = $RegistryWrites
        AppsAndFeaturesEvidence = @($ArpEvidence.Entries)
        UninstallString = $MsiUninstallString
        QuietUninstallString = $MsiQuietUninstallString
        DisplayIcon = $MsiDisplayIcon
        ExecutedPrograms = $ExecutedPrograms; OperationCounts = $OperationCounts
        EmbeddedMsi = $EmbeddedMsi; EmbeddedMsiPayloadRecord = $EmbeddedMsiPayloadRecord
        ExtractedFiles = $MsiInfo ? @('embedded.msi') : @(); CanExpand = [bool]$MsiInfo; OuterVersionInfo = $VersionStrings
        ParserVersionInfo = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.Wise'; ParserMajor = 2; Sources = @('Wise overlay and .WISE records', 'SabreTools WiseScript reader', 'validated MSI CFB and tables') }
      }
    } finally {
      $Stream.Dispose()
      Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Get-WiseEmbeddedMsiInfo {
  <#.SYNOPSIS Return exact embedded MSI evidence. .PARAMETER Path Path to the Wise installer.#>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)
  $Info = Get-WiseInfo -Path $Path
  if (-not $Info.EmbeddedMsi) { throw 'A validated Windows Installer database was not found in the Wise installer.' }
  return $Info.EmbeddedMsi
}

function Expand-WiseInstaller {
  <#
  .SYNOPSIS Export the exact MSI selected by a supported Wise route.
  .PARAMETER Path Path to the Wise installer.
  .PARAMETER DestinationPath Output MSI path; a temporary path is used when omitted.
  .PARAMETER CollisionAction Behavior selected only when the output path collides.
  #>
  [OutputType([IO.FileInfo])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt'
  )
  process {
    $SourcePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $TemporaryFile = New-TempFile
      $DestinationPath = [IO.Path]::ChangeExtension([string]$TemporaryFile, '.msi')
      Remove-Item -LiteralPath $TemporaryFile -Force
    }
    if ([IO.Path]::GetExtension($DestinationPath) -ine '.msi') { $DestinationPath = [IO.Path]::ChangeExtension($DestinationPath, '.msi') }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $Target = Resolve-InstallerExtractionTarget -DestinationPath ([IO.Path]::GetDirectoryName($DestinationPath)) -RelativePath ([IO.Path]::GetFileName($DestinationPath)) -CollisionAction $CollisionAction
    if (-not $Target.ShouldWrite) { return $null }

    $Scratch = New-TempFolder
    $Source = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Context = Get-WiseStructuralContext -Stream $Source
      if ($Context.MsiRange) {
        $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BinaryStreamRange -Source $Source -Destination $Output -Offset $Context.MsiRange.Offset -Length $Context.MsiRange.Length } finally { $Output.Dispose() }
      } else {
        $Nested = Get-WiseNestedMsiEvidence -Stream $Source -Context $Context -TemporaryFolder $Scratch
        if (-not $Nested) { throw 'The supported WiseScript media does not contain a validated nested MSI.' }
        Copy-Item -LiteralPath $Nested.MsiPath -Destination $Target.Path -Force
      }
      return Get-Item -LiteralPath $Target.Path -Force
    } finally {
      $Source.Dispose()
      Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Test-WiseInstaller {
  <#.SYNOPSIS Test whether a file contains a supported Wise route. .PARAMETER Path Path to the candidate installer.#>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $Stream = $null
    try {
      $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      $null = Get-WiseStructuralContext -Stream $Stream
      return $true
    } catch {
      return $false
    } finally {
      if ($Stream) { $Stream.Dispose() }
    }
  }
}

function Read-ProductVersionFromWise {
  <#.SYNOPSIS Read the authoritative product version. .PARAMETER Path Path to the Wise installer.#>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromWise {
  <#.SYNOPSIS Read the authoritative product name. .PARAMETER Path Path to the Wise installer.#>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).DisplayName }
}

function Read-PublisherFromWise {
  <#.SYNOPSIS Read the authoritative publisher. .PARAMETER Path Path to the Wise installer.#>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromWise {
  <#.SYNOPSIS Read the visible ARP ProductCode. .PARAMETER Path Path to the Wise installer.#>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).ProductCode }
}

function Read-UpgradeCodeFromWise {
  <#.SYNOPSIS Read the authoritative nested MSI UpgradeCode. .PARAMETER Path Path to the Wise installer.#>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).UpgradeCode }
}

function Read-ScopeFromWise {
  <#.SYNOPSIS Read explicit installation-scope evidence. .PARAMETER Path Path to the Wise installer.#>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).Scope }
}

function Read-ProtocolsFromWise {
  <#.SYNOPSIS Read protocol associations from the authoritative payload. .PARAMETER Path Path to the Wise installer.#>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromWise {
  <#.SYNOPSIS Read file-extension associations from the authoritative payload. .PARAMETER Path Path to the Wise installer.#>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).FileExtensions }
}

Export-ModuleMember -Function Get-WiseInfo, Get-WiseEmbeddedMsiInfo, Expand-WiseInstaller, Test-WiseInstaller, Read-ProductVersionFromWise, Read-ProductNameFromWise, Read-PublisherFromWise, Read-ProductCodeFromWise, Read-UpgradeCodeFromWise, Read-ScopeFromWise, Read-ProtocolsFromWise, Read-FileExtensionsFromWise
