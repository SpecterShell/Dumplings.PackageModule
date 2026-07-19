# SPDX-License-Identifier: MIT
# Static CreateInstall parser for Gentee launcher programs and GEA v2 archives.
# The container logic is PowerShell; the adaptive-Huffman LZGE decoder is an
# attributed MIT asset. Binary structures consumed here use LE integers:
#
#   PE setup
#     +-- .gentee section
#     |   +-- optional embedded runtime DLL
#     |   `-- [expanded-size:u32][LZGE-compressed GE program]
#     `-- GEA overlay
#     +00 47 45 41 00 ("GEA\0")
#     +04 volume:u16, +06 id:u32, +0A/+0B version bytes
#     +14 flags:u32, +1A header-size:u32, +1E summary-size:i64
#     +26 info-size:u32, +2A/+32/+3A archive/volume sizes:i64
#     +42 moved-size:u32, +46 memory/block/solid multipliers
#     `-- catalog -> [order:u8][packed-size:u32/u64][packed data]*
#         +-- type 0: stored bytes
#         +-- type 1: LZGE adaptive-Huffman stream
#         `-- type 2: modified PPMd-I range stream + end marker
#
# Integers are LE. GEA v1 uses 32-bit file/block sizes; v2 uses 64-bit sizes.
# The launcher header is identified by "Gentee Launcher\0" and records the
# runtime/program sizes and the header's own file offset. The decoded GE program
# is a sequence of bounded object records; direct calls to CreateInstall's
# source-verified addremoveext routine provide visible uninstall-key evidence.
# Password-protected records are never bypassed. PPMd is decoded by the bounded,
# source-shipped SharpCompress.Gentee managed provider, which preserves GEA's solid
# model state. SharpCompress's public PpmdStream implements standard H/H7Z/I1 models;
# it cannot decode GEA because Gentee changes I1 model behavior, allocator scheduling,
# and per-block framing.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:CreateInstallMaximumHeaderBytes = 268435456
$Script:CreateInstallMaximumInfoBytes = 268435456
$Script:CreateInstallMaximumEntries = 1000000
$Script:CreateInstallMaximumBlockBytes = 268435456
$Script:CreateInstallMaximumGenteeBytes = 67108864
$Script:CreateInstallFlagPassword = 0x0001
$Script:CreateInstallFlagCompressedInfo = 0x0002
$Script:CreateInstallFileFlagAttribute = 0x0001
$Script:CreateInstallFileFlagFolder = 0x0010
$Script:CreateInstallFileFlagVersion = 0x0020
$Script:CreateInstallFileFlagGroup = 0x0040
$Script:CreateInstallFileFlagProtect = 0x0080
$Script:CreateInstallFileFlagSolid = 0x0100
# Gentee 4.0 stores VM command operands according to this 218-entry shift table.
# Values 3/5/8 consume one BWD operand and 7/11 consume two; other values have
# no generic operand. Commands with raw or length-delimited operands are handled
# separately by Read-CreateInstallGenteeCommands.
$Script:CreateInstallGenteeCommandShift = [byte[]](
  6, 5, 5, 5, 3, 5, 3, 6, 6, 8, 8, 8, 11, 6, 8, 8, 6, 4, 6, 4, 9, 10, 9, 4, 6, 6, 6, 6, 6, 9, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  5, 9, 4, 8, 5, 5, 5, 6, 5, 7, 6, 5, 4, 2, 4, 4, 4, 4, 4, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 6, 9, 6, 9, 9, 6, 9, 6, 4, 4, 9, 6, 9, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
  1, 6, 9, 9, 9, 9, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 6, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 6, 4, 4, 4, 6, 6, 6, 6, 4, 4, 4, 4, 2, 2, 2, 2, 6, 1, 1, 1, 9, 9, 9, 9, 4, 4, 4, 4, 6, 6, 6,
  6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5
)

function Import-CreateInstallLzgeDecoder {
  <#
  .SYNOPSIS
    Load the MIT-licensed managed Gentee LZGE decoder once
  #>
  if (([Management.Automation.PSTypeName]'Dumplings.Gentee.LzgeDecoder').Type) { return }
  Use-InstallerRuntimeLoadLock {
    # Add-Type publishes types process-wide, so recheck after entering the loader lock to avoid a
    # duplicate-type race between Dumplings worker runspaces.
    if (([Management.Automation.PSTypeName]'Dumplings.Gentee.LzgeDecoder').Type) { return }
    $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'Source', 'CreateInstall', 'GenteeLzgeDecoder.cs'
    if (-not (Test-Path -LiteralPath $SourcePath)) { throw "The Gentee LZGE decoder source is missing: $SourcePath" }
    Add-Type -Path $SourcePath -ErrorAction Stop
  }
}

function Import-CreateInstallPpmdDecoder {
  <#
  .SYNOPSIS
    Load the source-shipped SharpCompress Gentee PPMd provider once.
  .DESCRIPTION
    Loads an AnyCPU managed companion provider. No native architecture selection or
    external CreateInstall/GEA executable is involved.
  #>
  param ()

  if (-not ([Management.Automation.PSTypeName]'SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder').Type) {
    Use-InstallerRuntimeLoadLock {
      # Add-Type publishes assemblies process-wide. Recheck under the shared loader lock so
      # concurrent parser runspaces cannot race to load the same provider twice.
      if (([Management.Automation.PSTypeName]'SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder').Type) { return }
      $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'Providers', 'SharpCompress.Gentee', 'SharpCompress.Gentee.dll'
      if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) { throw "The SharpCompress Gentee PPMd provider is missing: $AssemblyPath" }
      Add-Type -Path $AssemblyPath -ErrorAction Stop
    }
  }
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

  $Type = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit
  if ($Cursor.Value -ge $Limit) { throw 'The Gentee variable flags are truncated' }
  $Flags = $Bytes[$Cursor.Value]
  $Cursor.Value++
  if (($Flags -band 0x01) -ne 0) { $null = Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $Limit }
  if (($Flags -band 0x02) -ne 0) { $null = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit }
  if (($Flags -band 0x04) -ne 0) {
    if ($Cursor.Value -ge $Limit) { throw 'The Gentee variable dimensions are truncated' }
    $DimensionCount = $Bytes[$Cursor.Value]
    $Cursor.Value++
    for ($Index = 0; $Index -lt $DimensionCount; $Index++) { $null = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit }
  }
  if (($Flags -band 0x20) -eq 0) { return }

  # Primitive VM types store their fixed-width value directly. Strings are null terminated;
  # dynamically sized values carry a BWD length before their bytes.
  $PrimitiveSize = switch ($Type) {
    { $_ -in @(1, 2, 7, 11) } { 4; break }
    { $_ -in @(3, 4) } { 1; break }
    { $_ -in @(5, 6) } { 2; break }
    { $_ -in @(8, 9, 10) } { 8; break }
    default { $null }
  }
  if ($Type -eq 13) {
    $null = Read-CreateInstallGenteeString -Bytes $Bytes -Cursor $Cursor -Limit $Limit
  } elseif ($null -ne $PrimitiveSize) {
    if ($Cursor.Value + $PrimitiveSize -gt $Limit) { throw 'The Gentee primitive variable data is truncated' }
    $Cursor.Value += $PrimitiveSize
  } else {
    $DataSize = Read-CreateInstallGenteeBwd -Bytes $Bytes -Cursor $Cursor -Limit $Limit
    if ($DataSize -gt $Limit - $Cursor.Value) { throw 'The Gentee variable data exceeds its record' }
    $Cursor.Value += [int]$DataSize
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
  if ($Bytes[20] -ne 4) { throw "Unsupported Gentee GE major version '$($Bytes[20])'" }

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
  return [pscustomobject]@{
    Bytes             = $ProgramBytes
    Records           = $Records
    LauncherOffset    = [long]$HeaderOffsets[0]
    SectionOffset     = [long]$Section[0].RawOffset
    RuntimeSize       = [long]$RuntimeSize
    StoredProgramSize = [long]$ProgramRangeSize
    ProgramSize       = [long]$ProgramBytes.Length
    Packed            = $Packed
    VersionMajor      = [int]$ProgramBytes[20]
    VersionMinor      = [int]$ProgramBytes[21]
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
  return $Commands.ToArray()
}

function Get-CreateInstallUninstallEvidence {
  <#
  .SYNOPSIS
    Resolve source-verified CreateInstall Add/Remove calls from compiled GE bytecode.
  .PARAMETER Path
    Path to a CreateInstall setup executable. The file is opened read-only and never executed.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $Program = Get-CreateInstallGenteeProgram -Path $Path
  $UninstallPath = [Text.Encoding]::ASCII.GetBytes('Software\Microsoft\Windows\CurrentVersion\Uninstall\')
  $RequiredValueNames = @('UninstallString', 'DisplayName', 'NoModify', 'NoRepair')
  $CandidateRoutines = @($Program.Records | Where-Object Type -EQ 3 | Where-Object {
      $Record = $_
      $PathMatch = @(Find-BinaryPattern -Bytes $Program.Bytes -Pattern $UninstallPath -StartOffset $Record.PayloadOffset -Length ($Record.EndOffset - $Record.PayloadOffset) -Maximum 1).Count -eq 1
      if (-not $PathMatch) { return $false }
      foreach ($ValueName in $RequiredValueNames) {
        if (@(Find-BinaryPattern -Bytes $Program.Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes($ValueName)) -StartOffset $Record.PayloadOffset -Length ($Record.EndOffset - $Record.PayloadOffset) -Maximum 1).Count -eq 0) { return $false }
      }
      return $true
    })
  if ($CandidateRoutines.Count -ne 1) { throw 'The compiled CreateInstall program does not identify one built-in Add/Remove routine' }

  $Calls = [System.Collections.Generic.List[object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Commands = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($Commands[$CommandIndex].Command -ne $CandidateRoutines[0].Id) { continue }
      # addremoveext receives four literal strings (key/display name, icon path, icon file, and
      # estimated size) plus the current-user flag. Generated project code leaves those literals
      # adjacent to the direct function call even when helper conversions use local variables.
      $StringCommands = @($Commands[([Math]::Max(0, $CommandIndex - 64))..($CommandIndex - 1)] | Where-Object Command -EQ 34 | Select-Object -Last 4)
      if ($StringCommands.Count -ne 4) { continue }
      $CurrentUserCommands = @($Commands[($StringCommands[2].Index + 1)..($StringCommands[3].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -in @(0, 1) })
      if ($CurrentUserCommands.Count -eq 0) { continue }
      $Calls.Add([pscustomobject]@{
          RoutineId         = [uint32]$CandidateRoutines[0].Id
          CallerId          = [uint32]$Record.Id
          CallerName        = $Record.Name
          CallOffset        = [int]$Commands[$CommandIndex].Offset
          UninstallKeyName  = [string]$StringCommands[0].Operand
          IconPath          = [string]$StringCommands[1].Operand
          IconFile          = [string]$StringCommands[2].Operand
          ForCurrentUser    = [bool]$CurrentUserCommands[-1].Operand
          EstimatedSizeText = [string]$StringCommands[3].Operand
        })
    }
  }
  return [pscustomobject]@{
    Calls       = $Calls.ToArray()
    ProgramInfo = [pscustomobject]@{
      LauncherOffset     = $Program.LauncherOffset
      SectionOffset      = $Program.SectionOffset
      RuntimeSize        = $Program.RuntimeSize
      StoredProgramSize  = $Program.StoredProgramSize
      ProgramSize        = $Program.ProgramSize
      Packed             = $Program.Packed
      VersionMajor       = $Program.VersionMajor
      VersionMinor       = $Program.VersionMinor
      ObjectCount        = $Program.Records.Count
      AddRemoveRoutineId = [uint32]$CandidateRoutines[0].Id
    }
  }
}

function Read-CreateInstallNullTerminatedString {
  <#
  .SYNOPSIS
    Read one bounded UTF-8 null-terminated string from a byte array
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$Offset,
    [ValidateRange(1, 1048576)][int]$MaximumBytes = 65536
  )

  if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) { throw 'The GEA string offset is outside the metadata table' }
  $End = [Array]::IndexOf($Bytes, [byte]0, $Offset, [Math]::Min($MaximumBytes, $Bytes.Length - $Offset))
  if ($End -lt 0) { throw 'The GEA metadata contains an unterminated string' }
  [pscustomobject]@{ Value = [Text.Encoding]::UTF8.GetString($Bytes, $Offset, $End - $Offset); NextOffset = $End + 1 }
}

function Read-CreateInstallArchiveLogicalRange {
  <#
  .SYNOPSIS
    Read a logical GEA data range across normal and moved data regions
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Count
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Count
  )

  if ($Offset -lt 0 -or $Offset + $Count -gt $Layout.SummarySize) { throw 'The requested GEA logical range is outside the compressed data stream' }
  # GEA exposes one logical compressed stream even though moved bytes are physically stored before
  # ordinary data. Translate each requested slice without joining the complete archive in memory.
  $Result = [byte[]]::new($Count)
  if ($Count -eq 0) { return , $Result }
  $Stream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Remaining = $Count
    $LogicalOffset = $Offset
    $DestinationOffset = 0
    while ($Remaining -gt 0) {
      if ($LogicalOffset -lt $Layout.OrdinaryDataLength) {
        # Logical data starts in the ordinary region and wraps into the moved prefix at its end.
        $Available = $Layout.OrdinaryDataLength - $LogicalOffset
        $PhysicalOffset = $Layout.ArchiveOffset + $Layout.HeaderSize + $Layout.MovedSize + $LogicalOffset
      } else {
        $MovedOffset = $LogicalOffset - $Layout.OrdinaryDataLength
        $Available = $Layout.MovedSize - $MovedOffset
        $PhysicalOffset = $Layout.ArchiveOffset + $Layout.HeaderSize + $MovedOffset
      }
      $ReadCount = [int][Math]::Min($Remaining, $Available)
      if ($ReadCount -le 0) { throw 'The GEA logical range crosses an unavailable volume' }
      $Chunk = Read-BinaryBytes -Stream $Stream -Offset $PhysicalOffset -Count $ReadCount
      [Array]::Copy($Chunk, 0, $Result, $DestinationOffset, $ReadCount)
      $Remaining -= $ReadCount
      $DestinationOffset += $ReadCount
      $LogicalOffset += $ReadCount
    }
  } finally { $Stream.Dispose() }
  return , $Result
}

function ConvertFrom-CreateInstallFileTable {
  <#
  .SYNOPSIS
    Parse packed GEA v1/v2 file descriptors from an expanded metadata table
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER MajorVersion
    Detected format variant controlling version-specific parsing rules.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateSet(1, 2)][int]$MajorVersion
  )

  $Offset = 0
  $LogicalOffset = 0L
  $CurrentAttribute = 0
  $CurrentGroup = 0
  $CurrentPassword = 0
  $CurrentFolder = ''
  $Entries = [System.Collections.Generic.List[object]]::new()
  # Descriptor flags make several fields stateful: omitted attributes, groups, passwords, and
  # folders inherit the most recently declared value.
  while ($Offset -lt $Bytes.Length) {
    if ($Entries.Count -ge $Script:CreateInstallMaximumEntries) { throw 'The GEA metadata exceeds the configured entry-count limit' }
    $BaseSize = if ($MajorVersion -ge 2) { 30 } else { 22 }
    if ($Offset + $BaseSize -gt $Bytes.Length) { throw 'The GEA file descriptor table is truncated' }
    $Flags = [BitConverter]::ToUInt16($Bytes, $Offset); $Offset += 2
    $FileTime = [BitConverter]::ToInt64($Bytes, $Offset); $Offset += 8
    # GEA v2 widens both file sizes to 64 bits; the surrounding descriptor remains the same.
    if ($MajorVersion -ge 2) {
      $Size = [BitConverter]::ToUInt64($Bytes, $Offset); $Offset += 8
      $CompressedSize = [BitConverter]::ToUInt64($Bytes, $Offset); $Offset += 8
    } else {
      $Size = [uint64][BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
      $CompressedSize = [uint64][BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
    }
    $Crc32 = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
    $VersionHigh = $null; $VersionLow = $null
    if (($Flags -band $Script:CreateInstallFileFlagAttribute) -ne 0) { $CurrentAttribute = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    if (($Flags -band $Script:CreateInstallFileFlagVersion) -ne 0) { $VersionHigh = [BitConverter]::ToUInt32($Bytes, $Offset); $VersionLow = [BitConverter]::ToUInt32($Bytes, $Offset + 4); $Offset += 8 }
    if (($Flags -band $Script:CreateInstallFileFlagGroup) -ne 0) { $CurrentGroup = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    if (($Flags -band $Script:CreateInstallFileFlagProtect) -ne 0) { $CurrentPassword = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    $NameData = Read-CreateInstallNullTerminatedString -Bytes $Bytes -Offset $Offset; $Name = $NameData.Value; $Offset = $NameData.NextOffset
    if (($Flags -band $Script:CreateInstallFileFlagFolder) -ne 0) { $FolderData = Read-CreateInstallNullTerminatedString -Bytes $Bytes -Offset $Offset; $CurrentFolder = $FolderData.Value; $Offset = $FolderData.NextOffset }
    if ([string]::IsNullOrWhiteSpace($Name)) { throw 'The GEA metadata contains an empty file name' }
    $RelativePath = if ($CurrentFolder) { Join-Path $CurrentFolder $Name } else { $Name }
    # DataOffset is in the logical compressed stream, not an absolute file position.
    $Entries.Add([pscustomobject]@{
        Index          = $Entries.Count
        Flags          = [uint16]$Flags
        FileTime       = [long]$FileTime
        Size           = [uint64]$Size
        CompressedSize = [uint64]$CompressedSize
        Crc32          = [uint32]$Crc32
        Attributes     = [uint32]$CurrentAttribute
        VersionHigh    = $VersionHigh
        VersionLow     = $VersionLow
        GroupId        = [uint32]$CurrentGroup
        PasswordId     = [uint32]$CurrentPassword
        IsSolid        = ($Flags -band $Script:CreateInstallFileFlagSolid) -ne 0
        Name           = $Name
        Folder         = $CurrentFolder
        FullName       = $RelativePath
        DataOffset     = [long]$LogicalOffset
      })
    $LogicalOffset += [long]$CompressedSize
  }
  return $Entries.ToArray()
}

function Get-CreateInstallArchiveLayout {
  <#
  .SYNOPSIS
    Locate and parse the self-extracting CreateInstall GEA archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  Import-CreateInstallLzgeDecoder
  $Signature = [byte[]](0x47, 0x45, 0x41, 0x00)
  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # SETUP_TEMP is stored as a standalone GEA resource inside CreateInstall's PE. Reuse this
    # layout parser for that bounded resource by recognizing GEA at offset zero; ordinary setup
    # executables continue scanning only after their validated PE image.
    $Prefix = if ($Stream.Length -ge $Signature.Length) { Read-BinaryBytes -Stream $Stream -Offset 0 -Count $Signature.Length } else { [byte[]]::new(0) }
    $OverlayOffset = if ($Prefix.Length -eq $Signature.Length -and (Test-BinarySequence -Left $Prefix -Right $Signature)) { 0L } else { Get-PEOverlayOffset -Stream $Stream }
  } finally { $Stream.Dispose() }
  # Search only after the PE image and validate every GEA candidate through its complete size map;
  # compiled signature strings in the setup stub are not archive evidence.
  foreach ($ArchiveOffset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Signature -StartOffset $OverlayOffset -Maximum 16)) {
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      if ($ArchiveOffset + 73 -gt $Stream.Length) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count 73
      $VolumeNumber = [BitConverter]::ToUInt16($Header, 4)
      $UniqueId = [BitConverter]::ToUInt32($Header, 6)
      $MajorVersion = $Header[10]
      $MinorVersion = $Header[11]
      if ($VolumeNumber -ne 0 -or $MajorVersion -notin @(1, 2)) { continue }
      $Flags = [BitConverter]::ToUInt32($Header, 20)
      $VolumeCount = [BitConverter]::ToUInt16($Header, 24)
      $HeaderSize = [BitConverter]::ToUInt32($Header, 26)
      $SummarySize = [BitConverter]::ToInt64($Header, 30)
      $InfoSize = [BitConverter]::ToUInt32($Header, 38)
      $ArchiveFileSize = [BitConverter]::ToInt64($Header, 42)
      $VolumeSize = [BitConverter]::ToInt64($Header, 50)
      $LastVolumeSize = [BitConverter]::ToInt64($Header, 58)
      $MovedSize = [BitConverter]::ToUInt32($Header, 66)
      $Memory = $Header[70]
      $BlockMultiplier = $Header[71]
      $SolidMultiplier = $Header[72]
      # Dumplings supports self-contained single-volume SFX archives only. Multi-volume patterns
      # are reported by rejection rather than followed outside the installer.
      if ($VolumeCount -ne 1 -or $HeaderSize -lt 74 -or $HeaderSize -gt $Script:CreateInstallMaximumHeaderBytes -or $InfoSize -gt $Script:CreateInstallMaximumInfoBytes) { continue }
      if ($ArchiveFileSize -le $ArchiveOffset -or $ArchiveFileSize -gt $File.Length -or $HeaderSize -gt $ArchiveFileSize - $ArchiveOffset) { continue }
      if ($SummarySize -lt 0 -or $MovedSize -gt $SummarySize) { continue }
      $OrdinaryDataLength = $ArchiveFileSize - $MovedSize - $HeaderSize - $ArchiveOffset
      if ($OrdinaryDataLength -lt 0 -or $OrdinaryDataLength + $MovedSize -ne $SummarySize) { continue }

      # Variable header data starts with the volume pattern, then optional password IDs, then the
      # compressed or stored file descriptor table.
      $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count ([int]$HeaderSize)
      $PatternData = Read-CreateInstallNullTerminatedString -Bytes $HeaderBytes -Offset 73
      $MetadataOffset = $PatternData.NextOffset
      if (($Flags -band $Script:CreateInstallFlagPassword) -ne 0) {
        if ($MetadataOffset + 2 -gt $HeaderBytes.Length) { continue }
        $PasswordCount = [BitConverter]::ToUInt16($HeaderBytes, $MetadataOffset)
        $MetadataOffset += 2 + ($PasswordCount * 4)
      } else { $PasswordCount = 0 }
      if ($MetadataOffset -gt $HeaderBytes.Length) { continue }
      if (($Flags -band $Script:CreateInstallFlagCompressedInfo) -ne 0) {
        $CompressedInfo = [byte[]]::new($HeaderBytes.Length - $MetadataOffset)
        [Array]::Copy($HeaderBytes, $MetadataOffset, $CompressedInfo, 0, $CompressedInfo.Length)
        $Metadata = [Dumplings.Gentee.LzgeDecoder]::Decode($CompressedInfo, [int]$InfoSize)
      } else {
        if ($MetadataOffset + $InfoSize -gt $HeaderBytes.Length) { continue }
        $Metadata = [byte[]]::new([int]$InfoSize)
        [Array]::Copy($HeaderBytes, $MetadataOffset, $Metadata, 0, [int]$InfoSize)
      }
      # Require the catalog's final logical data extent to equal SummarySize before accepting the
      # candidate archive.
      $Entries = @(ConvertFrom-CreateInstallFileTable -Bytes $Metadata -MajorVersion $MajorVersion)
      if ($Entries.Count -eq 0 -or ($Entries[-1].DataOffset + [long]$Entries[-1].CompressedSize) -ne $SummarySize) { continue }
      return [pscustomobject]@{
        Path               = $File.FullName
        ArchiveOffset      = [long]$ArchiveOffset
        UniqueId           = [uint32]$UniqueId
        MajorVersion       = [byte]$MajorVersion
        MinorVersion       = [byte]$MinorVersion
        Flags              = [uint32]$Flags
        VolumeCount        = [uint16]$VolumeCount
        HeaderSize         = [long]$HeaderSize
        SummarySize        = [long]$SummarySize
        InfoSize           = [long]$InfoSize
        ArchiveFileSize    = [long]$ArchiveFileSize
        VolumeSize         = [long]$VolumeSize
        LastVolumeSize     = [long]$LastVolumeSize
        MovedSize          = [long]$MovedSize
        OrdinaryDataLength = [long]$OrdinaryDataLength
        PasswordCount      = [int]$PasswordCount
        MemoryMegabytes    = [int]$Memory
        BlockSize          = [long]$BlockMultiplier * 0x40000
        SolidSize          = [long]$SolidMultiplier * 0x40000
        VolumePattern      = $PatternData.Value
        Entries            = $Entries
      }
    } catch {
      # A structurally invalid candidate may be payload data containing GEA\0; continue scanning.
      continue
    } finally { $Stream.Dispose() }
  }
  throw 'The PE overlay does not contain a supported CreateInstall GEA archive'
}

function Get-CreateInstallBlockInfo {
  <#
  .SYNOPSIS
    Enumerate compression block headers for one GEA file entry
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][psobject]$Layout, [Parameter(Mandatory)][psobject]$Entry)

  $LogicalOffset = [long]$Entry.DataOffset
  $CompressedRemaining = [long]$Entry.CompressedSize
  $OutputRemaining = [long]$Entry.Size
  $HeaderSize = if ($Layout.MajorVersion -ge 2) { 9 } else { 5 }
  # Walk each entry's complete block stream and verify that compressed and expanded totals converge
  # exactly at the declared file boundaries.
  while ($OutputRemaining -gt 0) {
    if ($CompressedRemaining -lt $HeaderSize) { throw "The GEA data for '$($Entry.FullName)' is truncated" }
    $Header = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $LogicalOffset -Count $HeaderSize
    $RawOrder = $Header[0]
    $StoredOrder = $RawOrder -band 0x7F
    $CompressedSize = if ($Layout.MajorVersion -ge 2) { [uint64][BitConverter]::ToUInt64($Header, 1) } else { [uint64][BitConverter]::ToUInt32($Header, 1) }
    if ($CompressedSize -gt [long]::MaxValue -or $CompressedSize -gt $CompressedRemaining - $HeaderSize) { throw "The GEA block for '$($Entry.FullName)' exceeds its file data range" }
    # The high nibble selects Store/LZGE/PPMd; the low nibble carries the compression-order mode.
    $CompressionType = $StoredOrder -shr 4
    $CompressionOrder = ($StoredOrder -band 0x0F) + 1
    $OutputSize = if ($CompressionType -eq 0) { [long]$CompressedSize } else { [Math]::Min([long]$Layout.BlockSize, $OutputRemaining) }
    if ($OutputSize -le 0 -or $OutputSize -gt $OutputRemaining) { throw "The GEA block for '$($Entry.FullName)' has an invalid output size" }
    [pscustomobject]@{
      RawOrder         = [byte]$RawOrder
      CompressionType  = [int]$CompressionType
      CompressionName  = switch ($CompressionType) { 0 { 'Store' } 1 { 'LZGE' } 2 { 'PPMd' } default { 'Unknown' } }
      CompressionOrder = [int]$CompressionOrder
      HeaderOffset     = [long]$LogicalOffset
      DataOffset       = [long]($LogicalOffset + $HeaderSize)
      CompressedSize   = [long]$CompressedSize
      OutputSize       = [long]$OutputSize
    }
    $LogicalOffset += $HeaderSize + [long]$CompressedSize
    $CompressedRemaining -= $HeaderSize + [long]$CompressedSize
    $OutputRemaining -= $OutputSize
  }
  if ($CompressedRemaining -ne 0) { throw "The GEA file '$($Entry.FullName)' has trailing compressed data" }
}

function Get-CreateInstallInfo {
  <#
  .SYNOPSIS
    Read static CreateInstall identity and GEA payload evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Layout = Get-CreateInstallArchiveLayout -Path $File.FullName
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    $ProductName = ([string]$VersionInfo.ProductName).Trim()
    $DisplayVersion = ([string]$VersionInfo.ProductVersion).Trim()
    $Publisher = ([string]$VersionInfo.CompanyName).Trim()
    $CompressionMethods = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    # Enumerate block headers without expanding payloads so capability warnings remain inexpensive.
    foreach ($Entry in $Layout.Entries) { foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry)) { $null = $CompressionMethods.Add($Block.CompressionName) } }
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $RegistryWrites = [System.Collections.Generic.List[object]]::new()
    $ProductCodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $DetectedScopes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Decode the compiled install script independently of the payload archive. A source-verified
    # call to addremoveext proves both the uninstall subkey and the built-in scope rule.
    $UninstallEvidence = $null
    try { $UninstallEvidence = Get-CreateInstallUninstallEvidence -Path $File.FullName } catch {
      $Warnings.Add("The compiled CreateInstall uninstall program could not be parsed: $($_.Exception.Message)")
    }
    foreach ($Call in @($UninstallEvidence.Calls)) {
      $UninstallKeyName = ([string]$Call.UninstallKeyName).Trim()
      if ([string]::IsNullOrWhiteSpace($UninstallKeyName) -or $UninstallKeyName -ieq '#progname#') { $UninstallKeyName = $ProductName }
      if ([string]::IsNullOrWhiteSpace($UninstallKeyName)) {
        $Warnings.Add('CreateInstall invokes the Add/Remove command but its default program name is empty.')
        continue
      }
      if ($UninstallKeyName -match '#[^#]+#') {
        $Warnings.Add("CreateInstall's uninstall key '$UninstallKeyName' contains a runtime macro and cannot be resolved statically.")
        continue
      }
      $null = $ProductCodes.Add($UninstallKeyName)
      $Root = if ($Call.ForCurrentUser) { 'HKCU' } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'HKLM' } else { 'SHCTX' }
      if ($Root -eq 'HKCU') { $null = $DetectedScopes.Add('user') } elseif ($Root -eq 'HKLM') { $null = $DetectedScopes.Add('machine') } else { $null = $DetectedScopes.Add('user'); $null = $DetectedScopes.Add('machine') }
      $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKeyName"
      # Only values whose inputs are statically known are materialized. Runtime paths such as
      # #setuppath# and #uninstexe# remain represented by the call evidence rather than guessed.
      $RegistryWrites.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = 'DisplayName'; Value = $UninstallKeyName; Type = 'REG_SZ'; Evidence = 'Gentee addremoveext call' })
      if ($DisplayVersion) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = 'DisplayVersion'; Value = $DisplayVersion; Type = 'REG_SZ'; Evidence = 'Gentee addremoveext call + PE ProductVersion' }) }
      if ($Publisher) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = 'Publisher'; Value = $Publisher; Type = 'REG_SZ'; Evidence = 'Gentee addremoveext call + PE CompanyName' }) }
      if ($Call.EstimatedSizeText -match '^\d+$') { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = 'EstimatedSize'; Value = [uint64]$Call.EstimatedSizeText; Type = 'REG_DWORD'; Evidence = 'Gentee addremoveext call' }) }
      $RegistryWrites.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = 'NoModify'; Value = 1; Type = 'REG_DWORD'; Evidence = 'Gentee addremoveext implementation' })
      $RegistryWrites.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = 'NoRepair'; Value = 1; Type = 'REG_DWORD'; Evidence = 'Gentee addremoveext implementation' })
    }
    $ProductCode = if ($ProductCodes.Count -eq 1) { @($ProductCodes)[0] } else { $null }
    if ($ProductCodes.Count -gt 1) { $Warnings.Add("CreateInstall writes multiple uninstall keys: $(@($ProductCodes | Sort-Object) -join ', ').") }
    if ($ProductCodes.Count -eq 0) { $Warnings.Add('CreateInstall PE version resources identify the package but the compiled program does not prove one visible uninstall key. Validate ProductCode and ARP fields in a VM.') }

    $RegistryWriteArray = $RegistryWrites.ToArray()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWriteArray
    if ($ExecutionLevel -ieq 'requireAdministrator' -and $ProductCodes.Count -eq 0) { $Warnings.Add('Machine scope is inferred from an explicit requireAdministrator application manifest.') }
    if ($Layout.PasswordCount -gt 0 -or ($Layout.Entries | Where-Object PasswordId -GT 0 | Select-Object -First 1)) { $Warnings.Add('The GEA archive contains password-protected files; encrypted entries are intentionally unsupported.') }
    # Compression capability is reported independently from identity evidence. Password-protected
    # entries and unknown method nibbles remain non-expandable; PPMd is supported statically.

    $Scope = if ($DetectedScopes.Count -eq 1) { @($DetectedScopes)[0] } elseif ($DetectedScopes.Count -gt 1) { $null } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'machine' } else { $null }
    $SupportedScopes = if ($DetectedScopes.Count -gt 0) { @($DetectedScopes | Sort-Object) } elseif ($ExecutionLevel -ieq 'requireAdministrator') { @('machine') } else { @() }

    [pscustomobject]@{
      InstallerType              = 'CreateInstall'
      ProductCode                = $ProductCode
      ProductCodeEvidence        = if ($ProductCode) { 'Compiled Gentee addremoveext uninstall-key argument' } else { $null }
      PackageName                = $ProductName
      DisplayName                = $ProductName
      ProductName                = $ProductName
      DisplayVersion             = $DisplayVersion
      Publisher                  = $Publisher
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = $Scope
      SupportedScopes            = $SupportedScopes
      ScopeEvidence              = if ($ProductCode) { 'Compiled addremoveext current-user flag plus PE requestedExecutionLevel' } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'PE requestedExecutionLevel' } else { $null }
      RequestedExecutionLevel    = $ExecutionLevel
      RegistryWrites             = $RegistryWriteArray
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry = if ($ProductCode) { $true } else { $null }
      GenteeProgram              = $UninstallEvidence.ProgramInfo
      UninstallRegistrations     = @($UninstallEvidence.Calls)
      GEA                        = [pscustomobject]@{ MajorVersion = $Layout.MajorVersion; MinorVersion = $Layout.MinorVersion; ArchiveOffset = $Layout.ArchiveOffset; HeaderSize = $Layout.HeaderSize; SummarySize = $Layout.SummarySize; MovedSize = $Layout.MovedSize; BlockSize = $Layout.BlockSize; SolidSize = $Layout.SolidSize; EntryCount = $Layout.Entries.Count; CompressionMethods = @($CompressionMethods | Sort-Object); UnsupportedCompressionMethods = @($CompressionMethods | Where-Object { $_ -eq 'Unknown' } | Sort-Object); PasswordCount = $Layout.PasswordCount }
      ExtractedFiles             = @($Layout.Entries.FullName)
      CanExpand                  = $Layout.PasswordCount -eq 0 -and -not $CompressionMethods.Contains('Unknown')
      Warnings                   = @($Warnings)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.CreateInstall'; ParserMajor = 3; Sources = @('PE version resource', 'PE application manifest', 'Gentee launcher/linkhead and GE 4.0 bytecode structures', 'CreateInstall addremoveext command source', 'Gentee GEA v1/v2 structures', 'Gentee LZGE decoder', 'Gentee-modified PPMd-I decoder') }
    }
  }
}

function Expand-CreateInstallInstaller {
  <#
  .SYNOPSIS
    Extract stored, LZGE-compressed, and PPMd-compressed files from a CreateInstall GEA archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    Import-CreateInstallLzgeDecoder
    $Layout = Get-CreateInstallArchiveLayout -Path $Path
    if ($Layout.PasswordCount -gt 0) { throw 'Password-protected CreateInstall GEA archives are intentionally unsupported' }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-CreateInstall-$([guid]::NewGuid().ToString('N'))") }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $ExpandedBytes = 0L
    $SolidHistory = [byte[]]::new(0)
    $PpmdDecoder = $null

    # Resolve the complete selection before decoding. The last selected index bounds the work while
    # every earlier entry still advances LZGE or PPMd solid state exactly as Gentee does.
    $SelectedEntries = [bool[]]::new($Layout.Entries.Count)
    $LastSelectedIndex = -1
    for ($EntryIndex = 0; $EntryIndex -lt $Layout.Entries.Count; $EntryIndex++) {
      if (Test-ExtractionPattern -Path $Layout.Entries[$EntryIndex].FullName -Pattern $Name) {
        $SelectedEntries[$EntryIndex] = $true
        $LastSelectedIndex = $EntryIndex
      }
    }
    if ($LastSelectedIndex -lt 0) { throw "No CreateInstall files matched '$Name'" }

    try {
      for ($EntryIndex = 0; $EntryIndex -le $LastSelectedIndex; $EntryIndex++) {
        $Entry = $Layout.Entries[$EntryIndex]
        if ($Entry.PasswordId -gt 0) { throw "The CreateInstall entry '$($Entry.FullName)' is password-protected and cannot be extracted" }
        if (-not $Entry.IsSolid) { $SolidHistory = [byte[]]::new(0) }
        $Selected = $SelectedEntries[$EntryIndex]
        $OutputPath = $null
        if ($Selected) {
          $ExpandedBytes += [long]$Entry.Size
          if ($ExpandedBytes -gt $MaximumExpandedBytes) { throw 'CreateInstall extraction exceeds the configured output limit' }
          $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
          $Parent = [IO.Path]::GetDirectoryName($OutputPath)
          if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        } else { $Output = $null }
        try {
          foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry)) {
            if ($Block.CompressedSize -gt $Script:CreateInstallMaximumBlockBytes -or $Block.OutputSize -gt $Script:CreateInstallMaximumBlockBytes) { throw "The CreateInstall block for '$($Entry.FullName)' exceeds the configured block limit" }
            $InputBytes = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $Block.DataOffset -Count ([int]$Block.CompressedSize)
            # Decode one bounded block at a time. Unknown methods fail before a partial output can be
            # presented as a complete extracted file.
            switch ($Block.CompressionType) {
              0 { $Decoded = $InputBytes; $SolidHistory = [byte[]]::new(0) }
              1 {
                $Prefix = if ($Block.CompressionOrder -eq 1) { $SolidHistory } else { [byte[]]::new(0) }
                $Decoded = [Dumplings.Gentee.LzgeDecoder]::Decode($InputBytes, [int]$Block.OutputSize, $Prefix)
                # Retain only the configured solid window rather than accumulating all prior output.
                $Combined = if ($Prefix.Length -gt 0) { $Prefix + $Decoded } else { $Decoded }
                $Keep = [int][Math]::Min($Layout.SolidSize, $Combined.Length)
                $SolidHistory = [byte[]]::new($Keep)
                if ($Keep -gt 0) { [Array]::Copy($Combined, $Combined.Length - $Keep, $SolidHistory, 0, $Keep) }
              }
              2 {
                if (-not $PpmdDecoder) {
                  if ($Layout.MemoryMegabytes -le 0) { throw 'The GEA header declares no PPMd model memory' }
                  Import-CreateInstallPpmdDecoder
                  $ModelBytes = [int]([uint32]$Layout.MemoryMegabytes * 1MB)
                  $PpmdDecoder = [SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder]::new($ModelBytes)
                }
                # Order greater than one initializes a model; order one continues the preceding model
                # after the decoder consumes that block's independent range-stream end marker.
                $InputStream = [IO.MemoryStream]::new($InputBytes, $false)
                try {
                  $Decoded = $PpmdDecoder.DecodeBlock($InputStream, $InputBytes.Length, [int]$Block.OutputSize, $Block.CompressionOrder)
                } finally { $InputStream.Dispose() }
                $SolidHistory = [byte[]]::new(0)
              }
              default { throw "The CreateInstall entry '$($Entry.FullName)' uses an unknown compression method" }
            }
            if ($Output) { $Output.Write($Decoded, 0, $Decoded.Length) }
          }
        } catch {
          if ($Output) { $Output.Dispose(); $Output = $null }
          if ($OutputPath) { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue }
          throw
        } finally { if ($Output) { $Output.Dispose() } }
        if ($Selected) {
          $OutputFile = Get-Item -LiteralPath $OutputPath -Force
          if ($OutputFile.Length -ne [long]$Entry.Size) {
            Remove-Item -LiteralPath $OutputFile.FullName -Force -ErrorAction SilentlyContinue
            throw "The extracted CreateInstall file '$($Entry.FullName)' has an unexpected length"
          }
          # Gentee seeds CRC32 with all bits set and does not apply the conventional final XOR.
          $GenteeCrc32 = [uint32]((Get-BinaryCrc32 -Path $OutputFile.FullName -MaximumBytes $MaximumExpandedBytes) -bxor [uint32]::MaxValue)
          if ($GenteeCrc32 -ne [uint32]$Entry.Crc32) {
            Remove-Item -LiteralPath $OutputFile.FullName -Force -ErrorAction SilentlyContinue
            throw "The extracted CreateInstall file '$($Entry.FullName)' failed its GEA CRC32 check"
          }
          $Result.Add($OutputFile)
        }
      }
    } finally {
      if ($PpmdDecoder) { $PpmdDecoder.Dispose() }
    }
    return $Result.ToArray()
  }
}

function Test-CreateInstall {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable CreateInstall GEA archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-CreateInstallInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal URL protocol names from CreateInstall registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal file extensions from CreateInstall registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayName }
}

function Read-PublisherFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromCreateInstall {
  <#
  .SYNOPSIS
    Read a literal CreateInstall uninstall key when available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).ProductCode }
}

function Read-ScopeFromCreateInstall {
  <#
  .SYNOPSIS
    Read CreateInstall scope from explicit elevation evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-CreateInstallInfo, Expand-CreateInstallInstaller, Test-CreateInstall, Read-ProtocolsFromCreateInstall, Read-FileExtensionsFromCreateInstall, Read-ProductVersionFromCreateInstall, Read-ProductNameFromCreateInstall, Read-PublisherFromCreateInstall, Read-ProductCodeFromCreateInstall, Read-ScopeFromCreateInstall
