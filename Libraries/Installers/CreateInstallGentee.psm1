# SPDX-License-Identifier: Apache-2.0
# Internal CreateInstall implementation. See CreateInstall.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# CreateInstall gentee implementation, imported locally by the public facade.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:CreateInstallFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'CreateInstallFormatCatalog.psd1')

if ([int]$Script:CreateInstallFormatCatalog.CatalogVersion -ne 5) { throw "Unsupported CreateInstall format catalog version '$($Script:CreateInstallFormatCatalog.CatalogVersion)'." }

$Script:CreateInstallMaximumEntries = 1000000

$Script:CreateInstallMaximumGenteeBytes = 67108864

$Script:CreateInstallGenteeCommandShift = [byte[]](
  6, 5, 5, 5, 3, 5, 3, 6, 6, 8, 8, 8, 11, 6, 8, 8, 6, 4, 6, 4, 9, 10, 9, 4, 6, 6, 6, 6, 6, 9, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  5, 9, 4, 8, 5, 5, 5, 6, 5, 7, 6, 5, 4, 2, 4, 4, 4, 4, 4, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 6, 9, 6, 9, 9, 6, 9, 6, 4, 4, 9, 6, 9, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
  1, 6, 9, 9, 9, 9, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 6, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 6, 4, 4, 4, 6, 6, 6, 6, 4, 4, 4, 4, 2, 2, 2, 2, 6, 1, 1, 1, 9, 9, 9, 9, 4, 4, 4, 4, 6, 6, 6,
  6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5
)

function Get-CreateInstallCatalogProfile {
  <#
  .SYNOPSIS
    Read one section of the validated family catalog without reparsing it.
  .PARAMETER Section
    Catalog section consumed by the archive, operation, or result-composition layer.
  .OUTPUTS
    Source-backed descriptors, treated as read-only by all internal consumers.
  #>
  param ([Parameter(Mandatory)][ValidateSet('CatalogVersion', 'ArchiveProfiles', 'ProgramProfiles', 'AddRemoveProfiles', 'OperationProfiles')][string]$Section)
  $Script:CreateInstallFormatCatalog[$Section]
}

function Import-CreateInstallLzgeDecoder {
  <#
  .SYNOPSIS
    Load the MIT-licensed managed Gentee LZGE decoder once
  #>
  $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Source', 'CreateInstall', 'GenteeLzgeDecoder.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.Gentee.LzgeDecoder'
}

function Read-CreateInstallGenteeBwd {
  <#
  .SYNOPSIS
    Read one bounded Gentee variable-width unsigned integer.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing record.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  if ($Cursor.Value -lt 0 -or $Cursor.Value -ge $Limit -or $Limit -gt $Bytes.Length) { throw 'The Gentee BWD value is outside its record' }
  $Lead = $Bytes[$Cursor.Value]
  $Cursor.Value++
  if ($Lead -le 187) { return [uint32]$Lead }
  if ($Lead -eq 254) {
    if ($Cursor.Value + 2 -gt $Limit) { throw 'The Gentee BWD uint16 is truncated' }
    $Value = [BitConverter]::ToUInt16($Bytes, $Cursor.Value)
    $Cursor.Value += 2
    return [uint32]$Value
  }
  if ($Lead -eq 255) {
    if ($Cursor.Value + 4 -gt $Limit) { throw 'The Gentee BWD uint32 is truncated' }
    $Value = [BitConverter]::ToUInt32($Bytes, $Cursor.Value)
    $Cursor.Value += 4
    return $Value
  }
  if ($Cursor.Value -ge $Limit) { throw 'The Gentee two-byte BWD value is truncated' }
  $Value = (255 * ($Lead - 188)) + $Bytes[$Cursor.Value]
  $Cursor.Value++
  return [uint32]$Value
}

function Read-CreateInstallGenteeString {
  <#
  .SYNOPSIS
    Read one bounded null-terminated UTF-8 string from a GE object record.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing record.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  if ($Cursor.Value -lt 0 -or $Cursor.Value -ge $Limit -or $Limit -gt $Bytes.Length) { throw 'The Gentee string is outside its record' }
  $End = [Array]::IndexOf($Bytes, [byte]0, $Cursor.Value, $Limit - $Cursor.Value)
  if ($End -lt 0) { throw 'The Gentee object contains an unterminated string' }
  $Value = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor.Value, $End - $Cursor.Value)
  $Cursor.Value = $End + 1
  return $Value
}

function Move-CreateInstallGenteeVariable {
  <#
  .SYNOPSIS
    Advance over one serialized Gentee variable descriptor.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing record.
  #>
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  $null = Read-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Limit
}

function Read-CreateInstallGenteeVariable {
  <#
  .SYNOPSIS
    Decode one serialized Gentee variable descriptor and its optional initial value.
  .PARAMETER Bytes
    Decoded GE program bytes. The array is not modified.
  .PARAMETER Cursor
    Mutable object with a Value property containing the current GE-relative byte offset.
  .PARAMETER Limit
    Exclusive GE-relative end offset for the containing object record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Cursor,
    [Parameter(Mandatory)][int]$Limit
  )

  $Type = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit
  if ($Cursor.Value -ge $Limit) { throw 'The Gentee variable flags are truncated' }
  $Flags = $Bytes[$Cursor.Value]
  $Cursor.Value++
  $Name = if (($Flags -band 0x01) -ne 0) { Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $Limit } else { $null }
  $OfType = if (($Flags -band 0x02) -ne 0) { Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit } else { $null }
  $Dimensions = [System.Collections.Generic.List[uint32]]::new()
  if (($Flags -band 0x04) -ne 0) {
    if ($Cursor.Value -ge $Limit) { throw 'The Gentee variable dimensions are truncated' }
    $DimensionCount = $Bytes[$Cursor.Value]
    $Cursor.Value++
    for ($Index = 0; $Index -lt $DimensionCount; $Index++) { $Dimensions.Add((Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit)) }
  }

  $DataOffset = $null
  $Data = $null
  $Value = $null
  if (($Flags -band 0x20) -ne 0) {
    # GE stores stack primitives inline, strings as NUL-terminated UTF-8, and non-stack values
    # such as buf with a BWD byte length. Preserve the raw bytes for structured project lists.
    $PrimitiveSize = switch ($Type) {
      { $_ -in @(1, 2, 7, 11) } { 4; break }
      { $_ -in @(3, 4) } { 1; break }
      { $_ -in @(5, 6) } { 2; break }
      { $_ -in @(8, 9, 10) } { 8; break }
      default { $null }
    }
    if ($Type -eq 13) {
      $DataOffset = $Cursor.Value
      $Value = Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $Limit
      $Data = [Text.Encoding]::UTF8.GetBytes($Value)
    } else {
      $DataSize = if ($null -ne $PrimitiveSize) { [uint32]$PrimitiveSize } else { Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit }
      if ($DataSize -gt $Limit - $Cursor.Value) { throw 'The Gentee variable data exceeds its record' }
      $DataOffset = $Cursor.Value
      $Data = [byte[]]::new([int]$DataSize)
      if ($DataSize -gt 0) { [Array]::Copy($Bytes, $Cursor.Value, $Data, 0, [int]$DataSize) }
      $Cursor.Value += [int]$DataSize
      $Value = switch ($Type) {
        1 { [BitConverter]::ToInt32($Data, 0); break }
        2 { [BitConverter]::ToUInt32($Data, 0); break }
        3 { [sbyte]$Data[0]; break }
        4 { [byte]$Data[0]; break }
        5 { [BitConverter]::ToInt16($Data, 0); break }
        6 { [BitConverter]::ToUInt16($Data, 0); break }
        7 { [BitConverter]::ToSingle($Data, 0); break }
        8 { [BitConverter]::ToDouble($Data, 0); break }
        9 { [BitConverter]::ToInt64($Data, 0); break }
        10 { [BitConverter]::ToUInt64($Data, 0); break }
        default { $null }
      }
    }
  }

  return [pscustomobject]@{
    Type       = [uint32]$Type
    Flags      = [byte]$Flags
    Name       = $Name
    OfType     = $OfType
    Dimensions = $Dimensions.ToArray()
    HasData    = ($Flags -band 0x20) -ne 0
    DataOffset = $DataOffset
    Data       = $Data
    Value      = $Value
  }
}

function Get-CreateInstallGenteeRecord {
  <#
  .SYNOPSIS
    Enumerate bounded objects in a decoded Gentee 4.0 program.
  .PARAMETER Bytes
    Complete decoded GE program beginning with the GE header.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -lt 22 -or [BitConverter]::ToUInt32($Bytes, 0) -ne 0x00004547) { throw 'The decoded CreateInstall program does not have a Gentee GE header' }
  $HeaderSize = [BitConverter]::ToUInt32($Bytes, 12)
  $ProgramSize = [BitConverter]::ToUInt32($Bytes, 16)
  if ($HeaderSize -lt 22 -or $HeaderSize -gt $ProgramSize -or $ProgramSize -gt $Bytes.Length -or $ProgramSize -gt $Script:CreateInstallMaximumGenteeBytes) { throw 'The Gentee GE header declares invalid bounds' }
  # Match the reference Gentee ge_load validation: the header CRC covers bytes 12..ProgramSize and
  # Gentee's crc() applies no final inversion, so the standard CRC32 is inverted for comparison.
  $StoredCrc = [BitConverter]::ToUInt32($Bytes, 8)
  if (((Get-BinaryCrc32 -Bytes $Bytes -Offset 12 -Count ([int]$ProgramSize - 12)) -bxor [uint32]::MaxValue) -ne $StoredCrc) { throw 'The Gentee GE program fails its header CRC check' }
  $ProgramProfile = @($Script:CreateInstallFormatCatalog.ProgramProfiles | Where-Object { [int]$_.MajorVersion -eq [int]$Bytes[20] })
  if ($ProgramProfile.Count -ne 1) { throw "Unsupported Gentee GE major version '$($Bytes[20])'" }

  $Records = [System.Collections.Generic.List[object]]::new()
  $Offset = [int]$HeaderSize
  $NextObjectId = 1024
  while ($Offset -lt $ProgramSize) {
    if ($Records.Count -ge $Script:CreateInstallMaximumEntries -or $Offset + 6 -gt $ProgramSize) { throw 'The Gentee object table is truncated or excessive' }
    $Type = $Bytes[$Offset]
    $Flags = [BitConverter]::ToUInt32($Bytes, $Offset + 1)
    $Cursor = [pscustomobject]@{ Value = $Offset + 5 }
    $RecordSize = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $ProgramSize
    if ($RecordSize -lt $Cursor.Value - $Offset -or $RecordSize -gt $ProgramSize - $Offset) { throw 'A Gentee object record exceeds the GE program' }
    $EndOffset = $Offset + [int]$RecordSize
    $Name = if (($Flags -band 0x0001) -ne 0) { Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $EndOffset } else { $null }
    # The leading resource record is serialized outside the VM object table. All following records
    # retain their VM identifiers beginning at KERNEL_COUNT (1024).
    $ObjectId = if ($Type -eq 9) { $null } else { $CurrentId = $NextObjectId; $NextObjectId++; $CurrentId }
    $Records.Add([pscustomobject]@{
        Id            = $ObjectId
        Type          = [int]$Type
        Flags         = [uint32]$Flags
        Name          = $Name
        Offset        = $Offset
        PayloadOffset = [int]$Cursor.Value
        EndOffset     = $EndOffset
        Size          = [int]$RecordSize
      })
    $Offset = $EndOffset
  }
  if ($Offset -ne $ProgramSize) { throw 'The Gentee object records do not end at the declared program size' }
  return $Records.ToArray()
}

function Get-CreateInstallGenteeProgram {
  <#
  .SYNOPSIS
    Decode the bounded Gentee program embedded in a CreateInstall PE section.
  .PARAMETER Path
    Path to a CreateInstall setup executable. The file is opened read-only and never executed.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  Import-CreateInstallLzgeDecoder
  $File = Get-Item -LiteralPath $Path -Force
  $Layout = Get-PELayout -Path $File.FullName
  $Section = @($Layout.Sections | Where-Object Name -EQ '.gentee')
  if ($Section.Count -ne 1) { throw 'The CreateInstall PE does not contain one .gentee section' }
  $LauncherSignature = [Text.Encoding]::ASCII.GetBytes("Gentee Launcher`0")
  $SearchLength = [Math]::Min(131072L, $File.Length)
  $HeaderOffsets = @(Find-BinaryPattern -Path $File.FullName -Pattern $LauncherSignature -Length $SearchLength -Maximum 4)
  if ($HeaderOffsets.Count -ne 1) { throw 'The Gentee launcher header could not be identified uniquely' }

  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # linkhead is packed: three byte fields precede an unaligned ushort and uint fields.
    $Header = Read-BinaryBytes -Stream $Stream -Offset $HeaderOffsets[0] -Count 113
    $Packed = $Header[26] -ne 0
    $RuntimeSize = [BitConverter]::ToUInt32($Header, 29)
    $ProgramRangeSize = [BitConverter]::ToUInt32($Header, 33)
    $RecordedHeaderOffset = [BitConverter]::ToUInt32($Header, 45)
    if ($RecordedHeaderOffset -ne $HeaderOffsets[0] -or $ProgramRangeSize -le 0 -or $ProgramRangeSize -gt $Script:CreateInstallMaximumGenteeBytes) { throw 'The Gentee launcher header has invalid program bounds' }
    if ($RuntimeSize -gt $Section[0].RawSize -or $ProgramRangeSize -gt $Section[0].RawSize - $RuntimeSize) { throw 'The Gentee launcher program exceeds the .gentee section' }
    $ProgramRange = Read-BinaryBytes -Stream $Stream -Offset ($Section[0].RawOffset + $RuntimeSize) -Count ([int]$ProgramRangeSize)
  } finally { $Stream.Dispose() }

  if ($Packed) {
    if ($ProgramRange.Length -lt 5) { throw 'The packed Gentee program is truncated' }
    $ExpandedSize = [BitConverter]::ToUInt32($ProgramRange, 0)
    if ($ExpandedSize -lt 22 -or $ExpandedSize -gt $Script:CreateInstallMaximumGenteeBytes) { throw 'The packed Gentee program declares an invalid expanded size' }
    $Compressed = [byte[]]::new($ProgramRange.Length - 4)
    [Array]::Copy($ProgramRange, 4, $Compressed, 0, $Compressed.Length)
    $ProgramBytes = [Dumplings.Gentee.LzgeDecoder]::Decode($Compressed, [int]$ExpandedSize)
  } else {
    $ProgramBytes = $ProgramRange
  }
  $Records = @(Get-CreateInstallGenteeRecord -Bytes $ProgramBytes)
  $ProgramProfile = @($Script:CreateInstallFormatCatalog.ProgramProfiles | Where-Object { [int]$_.MajorVersion -eq [int]$ProgramBytes[20] })[0]
  return [pscustomobject]@{
    Bytes                 = $ProgramBytes
    Records               = $Records
    LauncherOffset        = [long]$HeaderOffsets[0]
    SectionOffset         = [long]$Section[0].RawOffset
    RuntimeSize           = [long]$RuntimeSize
    StoredProgramSize     = [long]$ProgramRangeSize
    ProgramSize           = [long]$ProgramBytes.Length
    Packed                = $Packed
    VersionMajor          = [int]$ProgramBytes[20]
    VersionMinor          = [int]$ProgramBytes[21]
    ProgramProfile        = [string]$ProgramProfile.Id
    CommandCache          = [System.Collections.Generic.Dictionary[uint32, object]]::new()
    FunctionIndex         = $null
    ExternalFunctionIndex = $null
  }
}

function Get-CreateInstallGenteeCommand {
  <#
  .SYNOPSIS
    Decode command boundaries and literal operands from one GE bytecode record.
  .PARAMETER Program
    Decoded Gentee program and object records returned by Get-CreateInstallGenteeProgram.
  .PARAMETER Record
    One OVM_BYTECODE record from the decoded GE program.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$Record
  )

  if ($Record.Type -ne 3) { return @() }
  if ($null -ne $Record.Id -and $Program.PSObject.Properties['CommandCache'] -and $Program.CommandCache.ContainsKey([uint32]$Record.Id)) {
    return $Program.CommandCache[[uint32]$Record.Id]
  }
  $Bytes = $Program.Bytes
  $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
  # A bytecode object begins with its return descriptor, parameter descriptors, and grouped local
  # descriptors. Commands occupy the remaining bytes in the record.
  Move-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
  $ParameterCount = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
  for ($Index = 0; $Index -lt $ParameterCount; $Index++) { Move-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset }
  $SetCount = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
  $VariableCount = 0L
  for ($Index = 0; $Index -lt $SetCount; $Index++) { $VariableCount += Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset }
  if ($VariableCount -gt 1000000) { throw 'The Gentee bytecode declares excessive local variables' }
  for ($Index = 0; $Index -lt $VariableCount; $Index++) { Move-CreateInstallGenteeVariable -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset }

  $Commands = [System.Collections.Generic.List[object]]::new()
  while ($Cursor.Value -lt $Record.EndOffset) {
    $CommandOffset = $Cursor.Value
    $Command = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
    $Operand = $null
    if ($Command -ge 18 -and $Command -lt 236) {
      switch ($Command) {
        25 { if ($Cursor.Value + 1 -gt $Record.EndOffset) { throw 'A Gentee byte literal is truncated' }; $Operand = [uint32]$Bytes[$Cursor.Value]; $Cursor.Value++; break }
        26 { if ($Cursor.Value + 2 -gt $Record.EndOffset) { throw 'A Gentee ushort literal is truncated' }; $Operand = [uint32][BitConverter]::ToUInt16($Bytes, $Cursor.Value); $Cursor.Value += 2; break }
        27 { if ($Cursor.Value + 4 -gt $Record.EndOffset) { throw 'A Gentee uint literal is truncated' }; $Operand = [BitConverter]::ToUInt32($Bytes, $Cursor.Value); $Cursor.Value += 4; break }
        30 { if ($Cursor.Value + 8 -gt $Record.EndOffset) { throw 'A Gentee ulong literal is truncated' }; $Operand = [BitConverter]::ToUInt64($Bytes, $Cursor.Value); $Cursor.Value += 8; break }
        31 {
          $Count = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          if ($Count -gt ($Record.EndOffset - $Cursor.Value) / 4) { throw 'A Gentee command-list literal is truncated' }
          $Operand = [uint32]$Count
          $Cursor.Value += [int](4 * $Count)
          break
        }
        { $_ -in @(28, 29, 85) } { $Operand = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset; break }
        34 {
          $Length = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          if ($Length -gt $Record.EndOffset - $Cursor.Value) { throw 'A Gentee data literal exceeds its bytecode record' }
          $Operand = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor.Value, [int]$Length)
          $Cursor.Value += [int]$Length
          break
        }
        93 {
          $Count = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          if ($Count -gt ($Record.EndOffset - $Cursor.Value) / 4) { throw 'A Gentee assembler block is truncated' }
          $Operand = [uint32]$Count
          $Cursor.Value += [int](4 * $Count)
          break
        }
        default {
          $Shift = $Script:CreateInstallGenteeCommandShift[$Command - 18]
          if ($Shift -in @(7, 11)) {
            $Operand = @(
              Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
              Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
            )
          } elseif ($Shift -in @(3, 5, 8)) {
            $Operand = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Record.EndOffset
          }
        }
      }
    }
    $Commands.Add([pscustomobject]@{ Index = $Commands.Count; Offset = $CommandOffset; Command = [uint32]$Command; Operand = $Operand })
  }
  $Result = $Commands.ToArray()
  if ($null -ne $Record.Id -and $Program.PSObject.Properties['CommandCache']) { $Program.CommandCache[[uint32]$Record.Id] = $Result }
  return $Result
}

function Get-CreateInstallGenteeParameterCount {
  <#
  .SYNOPSIS
    Read the declared parameter count from one Gentee bytecode object.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER Record
    Bytecode record whose function signature is inspected.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$Record
  )

  if ($Record.Type -ne 3) { throw 'Only Gentee bytecode records declare function parameters' }
  $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
  Move-CreateInstallGenteeVariable -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
  return Read-CreateInstallGenteeBwd -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
}

function ConvertFrom-CreateInstallGenteeList {
  <#
  .SYNOPSIS
    Decode one bounded, offset-addressed list from CreateInstall's generated g_list buffer.
  .PARAMETER Bytes
    Complete initialized Gentee buf value containing generated project lists.
  .PARAMETER Offset
    Zero-based offset in Bytes. The list starts with a uint32 LE row count.
  .PARAMETER FieldCount
    Number of NUL-terminated UTF-8 fields serialized for each row.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset,
    [Parameter(Mandatory)][ValidateRange(1, 64)][int]$FieldCount
  )

  if ($Offset -gt $Bytes.Length - 4) { throw 'The Gentee list offset is outside g_list' }
  $Count = [BitConverter]::ToUInt32($Bytes, $Offset)
  if ($Count -gt $Script:CreateInstallMaximumEntries) { throw 'The Gentee list exceeds the configured row-count limit' }
  $Cursor = $Offset + 4
  $Rows = [System.Collections.Generic.List[object]]::new([int]$Count)
  for ($RowIndex = 0; $RowIndex -lt $Count; $RowIndex++) {
    $Fields = [string[]]::new($FieldCount)
    for ($FieldIndex = 0; $FieldIndex -lt $FieldCount; $FieldIndex++) {
      if ($Cursor -ge $Bytes.Length) { throw 'The Gentee list is truncated' }
      $End = [Array]::IndexOf($Bytes, [byte]0, $Cursor, $Bytes.Length - $Cursor)
      if ($End -lt 0) { throw 'The Gentee list contains an unterminated UTF-8 field' }
      $Fields[$FieldIndex] = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor, $End - $Cursor)
      $Cursor = $End + 1
    }
    $Rows.Add([pscustomobject]@{ Index = $RowIndex; Fields = $Fields })
  }
  return $Rows.ToArray()
}

function Get-CreateInstallFunctionIndex {
  <#
  .SYNOPSIS
    Build one reusable index of Gentee function signatures, commands, and literal text.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  #>
  [OutputType([System.Collections.Generic.Dictionary[uint32, object]])]
  param ([Parameter(Mandatory)][psobject]$Program)

  if ($null -ne $Program.FunctionIndex) { return $Program.FunctionIndex }
  $Functions = [System.Collections.Generic.Dictionary[uint32, object]]::new()
  $ExternalFunctions = Get-CreateInstallGenteeExternalFunctionIndex -Program $Program
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Commands = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
    $Functions[[uint32]$Record.Id] = [pscustomobject]@{
      Record         = $Record
      ParameterCount = Get-CreateInstallGenteeParameterCount -Program $Program -Record $Record
      Commands       = $Commands
      StringLiterals = [string[]]@($Commands | Where-Object Command -EQ 34 | ForEach-Object { [string]$_.Operand })
      ExternalCalls  = [object[]]@($Commands | Where-Object { $ExternalFunctions.ContainsKey([uint32]$_.Command) } | ForEach-Object { $ExternalFunctions[[uint32]$_.Command] })
      LiteralText    = [Text.Encoding]::ASCII.GetString($Program.Bytes, $Record.PayloadOffset, $Record.EndOffset - $Record.PayloadOffset)
    }
  }
  $Program.FunctionIndex = $Functions
  return $Functions
}

function Get-CreateInstallGenteeExternalFunctionIndex {
  <#
  .SYNOPSIS
    Decode linked-library and imported-function records from a GE program.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram. The result is cached on this
    object and no linked library body is loaded or executed.
  #>
  [OutputType([System.Collections.Generic.Dictionary[uint32, object]])]
  param ([Parameter(Mandatory)][psobject]$Program)

  if ($Program.PSObject.Properties['ExternalFunctionIndex'] -and $null -ne $Program.ExternalFunctionIndex) { return $Program.ExternalFunctionIndex }
  $Imports = [System.Collections.Generic.Dictionary[uint32, string]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 8)) {
    $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
    $Filename = Read-CreateInstallGenteeString -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
    if (($Record.Flags -band 0x0100) -ne 0) {
      if ($Cursor.Value + 4 -gt $Record.EndOffset) { throw 'A linked Gentee import has a truncated size' }
      $LinkedSize = [BitConverter]::ToUInt32($Program.Bytes, $Cursor.Value)
      $Cursor.Value += 4
      if ($LinkedSize -gt $Record.EndOffset - $Cursor.Value) { throw 'A linked Gentee import body exceeds its object record' }
      $Cursor.Value += [int]$LinkedSize
    }
    if ($Cursor.Value -ne $Record.EndOffset) { throw 'A Gentee import record contains trailing data' }
    $Imports[[uint32]$Record.Id] = $Filename
  }

  $ExternalFunctions = [System.Collections.Generic.Dictionary[uint32, object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 4)) {
    $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
    $null = Read-CreateInstallGenteeVariable -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
    $ParameterCount = Read-CreateInstallGenteeBwd -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
    for ($Index = 0; $Index -lt $ParameterCount; $Index++) { Move-CreateInstallGenteeVariable -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset }
    if (($Record.Flags -band 0x080000) -eq 0) { continue }
    $ImportId = Read-CreateInstallGenteeBwd -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
    $OriginalName = Read-CreateInstallGenteeString -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
    if ($Cursor.Value -ne $Record.EndOffset) { throw 'An imported Gentee function record contains trailing data' }
    $ExternalFunctions[[uint32]$Record.Id] = [pscustomobject]@{
      Id             = [uint32]$Record.Id
      Name           = $OriginalName
      ParameterCount = [uint32]$ParameterCount
      ImportId       = [uint32]$ImportId
      Library        = $Imports.ContainsKey([uint32]$ImportId) ? $Imports[[uint32]$ImportId] : $null
    }
  }
  $Program.ExternalFunctionIndex = $ExternalFunctions
  return $ExternalFunctions
}

Export-ModuleMember -Function Get-CreateInstallCatalogProfile, Import-CreateInstallLzgeDecoder, Read-CreateInstallGenteeBwd, Read-CreateInstallGenteeString, Move-CreateInstallGenteeVariable, Read-CreateInstallGenteeVariable, Get-CreateInstallGenteeRecord, Get-CreateInstallGenteeProgram, Get-CreateInstallGenteeCommand, Get-CreateInstallGenteeParameterCount, ConvertFrom-CreateInstallGenteeList, Get-CreateInstallFunctionIndex, Get-CreateInstallGenteeExternalFunctionIndex
