BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
  . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Cabinet.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShieldInstallScript.psm1') -Force
  $Script:InstallShieldFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallShield'

  function New-TestInstallScriptFile {
    param (
      [Parameter(Mandatory)][string]$Path,
      [string[]]$String = @(),
      [switch]$Scrambled
    )
    $Marker = 'Copyright (c) 1990-2002 InstallShield Software Corp. All Rights Reserved.'
    $Decoded = [Text.Encoding]::ASCII.GetBytes(([char[]](0x12, 0x34, 0x56, 0x78, 0, 0) -join '') + $Marker + [char]0 + ($String -join ([char]0)) + (([string][char]0) * 32))
    if ($Scrambled) {
      $Encoded = [byte[]]::new($Decoded.Length)
      for ($Index = 0; $Index -lt $Decoded.Length; $Index++) {
        $Value = ($Decoded[$Index] + ($Index % 71)) -band 0xFF
        $Rotated = (($Value -shl 2) -bor ($Value -shr 6)) -band 0xFF
        $Encoded[$Index] = [byte]($Rotated -bxor 0xF1)
      }
      [IO.File]::WriteAllBytes($Path, $Encoded)
    } else {
      [IO.File]::WriteAllBytes($Path, $Decoded)
    }
  }

  function New-TestLegacyInstallScriptBytes {
    $Stream = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
    try {
      $Writer.Write([byte[]](0xB8, 0xC9, 0x0C, 0x00))
      $Writer.Write([byte[]]::new(9))
      $Writer.Write([uint16]3)
      $Writer.Write([Text.Encoding]::ASCII.GetBytes('INS'))
      $Writer.Write([uint16]1) # event count
      $Writer.Write([uint16]0) # global strings
      $Writer.Write([uint16]0) # loadable strings
      $Writer.Write([uint16]0) # global numbers
      $Writer.Write([uint16]0) # loadable numbers
      $Writer.Write([uint16]0) # structures
      $Writer.Write([uint16]1) # prototypes
      $Writer.Write([byte]2)   # internal prototype
      $Writer.Write([byte]0)   # return type
      $Writer.Write([uint16]0) # DLL name
      $Writer.Write([uint16]7)
      $Writer.Write([Text.Encoding]::ASCII.GetBytes('program'))
      $Writer.Write([uint16]0) # event index
      $Writer.Write([uint16]0) # parameters
      $Writer.Write([uint16]0) # event reserved
      $Writer.Write([uint16]2) # actions
      $Writer.Write([uint16]0x13) # Assign
      $Writer.Write([byte]0x30)
      $Writer.Write([int16]1)
      $Writer.Write([byte]0x41)
      $Writer.Write([int32]7)
      $Writer.Write([uint16]0xB8) # Return without a value
      return $Stream.ToArray()
    } finally {
      $Writer.Dispose()
      $Stream.Dispose()
    }
  }

  function New-TestInstallScriptLibrary {
    param ([Parameter(Mandatory)][string]$Path)

    [byte[]]$Program = @(New-TestLegacyInstallScriptBytes)
    $Unknown = [byte[]](1, 2, 3, 4)
    $Names = @('legacy.ins', 'opaque.bin')
    $CatalogLength = 12 + (2 + $Names[0].Length + 8) + (2 + $Names[1].Length + 8)
    $Stream = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
    try {
      $Writer.Write([Text.Encoding]::ASCII.GetBytes('pOdA'))
      $Writer.Write([uint32]1)
      $Writer.Write([uint32]2)
      $Offset = $CatalogLength
      foreach ($Index in 0..1) {
        $Payload = $Index -eq 0 ? $Program : $Unknown
        $Writer.Write([uint16]$Names[$Index].Length)
        $Writer.Write([Text.Encoding]::ASCII.GetBytes($Names[$Index]))
        $Writer.Write([uint32]$Offset)
        $Writer.Write([uint32]$Payload.Length)
        $Offset += $Payload.Length
      }
      $Writer.Write([byte[]]$Program)
      $Writer.Write([byte[]]$Unknown)
      [IO.File]::WriteAllBytes($Path, $Stream.ToArray())
    } finally {
      $Writer.Dispose()
      $Stream.Dispose()
    }
  }

  function New-TestInstallScriptObjectModuleBytes {
    $Stream = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
    try {
      $Stream.SetLength(0x100)
      $Stream.Position = 0
      $Writer.Write([Convert]::ToUInt32('C9F34F48', 16))
      $Writer.Write([Text.Encoding]::ASCII.GetBytes('v3.99.002'.PadRight(12, [char]0)))
      $Writer.Write([Text.Encoding]::ASCII.GetBytes('Synthetic OBS fixture'.PadRight(80, [char]0)))
      $Stream.Position = 0x62
      $Writer.Write([uint16]2)

      $Stream.Position = 0x100
      $ExternalOffset = $Stream.Position
      $Writer.Write([uint16]1)
      $Writer.Write([byte]3)
      $Writer.Write([int16]-1)
      $Writer.Write([uint16]15)
      $Writer.Write([Text.Encoding]::ASCII.GetBytes('EXTERNAL_STRING'))

      $PrototypeOffset = $Stream.Position
      $Writer.Write([uint16]1)
      $Writer.Write([byte]0x0A) # Internal and exported.
      $Writer.Write([byte]8)    # Void return type.
      $Writer.Write([uint16]0)
      $Writer.Write([uint16]7)
      $Writer.Write([Text.Encoding]::ASCII.GetBytes('program'))
      $Writer.Write([uint16]0)
      $Writer.Write([uint16]0)

      $TypeOffset = $Stream.Position
      $Writer.Write([uint16]0)

      $AddressOffset = $Stream.Position
      $Writer.Write([uint16]1)
      $Writer.Write([byte]0)
      $AddressRecordPosition = $Stream.Position
      $Writer.Write([uint32]0)

      $BlockTableOffset = $Stream.Position
      $BlockRecordPosition = $Stream.Position
      $Writer.Write([uint32]0)
      $SecondBlockRecordPosition = $Stream.Position
      $Writer.Write([uint32]0)
      $BlockOffset = $Stream.Position
      $Writer.Write([uint16]3)
      $Writer.Write([uint16]0x22)
      $Writer.Write([uint16]1)
      $Writer.Write([byte]7)
      $Writer.Write([int32]0)
      $Writer.Write([uint16]0x01)
      $Writer.Write([uint16]0)
      $Writer.Write([uint16]0x26)
      $Writer.Write([uint16]0)
      $Writer.Write([uint16]0)
      $Writer.Write([uint16]0)
      $Writer.Write([uint16]0)
      $Writer.Write([uint16]0)
      $SecondBlockOffset = $Stream.Position
      $Writer.Write([uint16]0)

      $Stream.Position = $AddressRecordPosition
      $Writer.Write([uint32]$BlockOffset)
      $Stream.Position = $BlockRecordPosition
      $Writer.Write([uint32]$BlockOffset)
      $Stream.Position = $SecondBlockRecordPosition
      $Writer.Write([uint32]$SecondBlockOffset)
      $Stream.Position = 0x84
      $Writer.Write([uint32]$ExternalOffset)
      $Writer.Write([uint32]$PrototypeOffset)
      $Writer.Write([uint32]$TypeOffset)
      $Writer.Write([uint32]$AddressOffset)
      $Stream.Position = 0xD8
      $Writer.Write([uint32]$BlockTableOffset)
      return $Stream.ToArray()
    } finally {
      $Writer.Dispose()
      $Stream.Dispose()
    }
  }

  function New-TestInstallShieldMediaHeader {
    param (
      [Parameter(Mandatory)][string]$Path,
      [uint32]$RawVersion = 0x04000C80,
      [switch]$MalformedRegistryPointer
    )

    $DescriptorBase = 0x20
    $DescriptorSize = 0xC00
    $Bytes = [byte[]]::new($DescriptorBase + $DescriptorSize)
    $WriteUInt16 = { param([int]$Offset, [uint16]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt32 = { param([int]$Offset, [uint32]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteString = {
      param([uint32]$RelativeOffset, [string]$Value)
      $Encoded = [Text.Encoding]::Unicode.GetBytes($Value + [char]0)
      $Encoded.CopyTo($Bytes, $DescriptorBase + $RelativeOffset)
    }

    # Minimal valid ISc( catalog. No payload entries are required to exercise
    # descriptor-extension metadata, but the ordinary file table remains valid.
    & $WriteUInt32 0 ([uint32]0x28635349)
    & $WriteUInt32 4 $RawVersion
    & $WriteUInt32 12 ([uint32]$DescriptorBase)
    & $WriteUInt32 16 ([uint32]$DescriptorSize)
    & $WriteUInt32 ($DescriptorBase + 0x0C) ([uint32]0x880)
    & $WriteUInt32 ($DescriptorBase + 0x14) ([uint32]4)
    & $WriteUInt32 ($DescriptorBase + 0x18) ([uint32]4)
    & $WriteUInt32 ($DescriptorBase + 0x1C) ([uint32]0)
    & $WriteUInt32 ($DescriptorBase + 0x28) ([uint32]0)
    & $WriteUInt32 ($DescriptorBase + 0x2C) ([uint32]0)

    # One default HKLM registry set containing one REG_SZ value.
    & $WriteUInt32 ($DescriptorBase + 0x282) ([uint32]($MalformedRegistryPointer ? 0xFFFF : 0x300))
    if (-not $MalformedRegistryPointer) {
      & $WriteUInt16 ($DescriptorBase + 0x300) ([uint16]1)
      & $WriteUInt32 ($DescriptorBase + 0x302) ([uint32]0x310)
      & $WriteUInt32 ($DescriptorBase + 0x310) ([uint32]0x320)
      & $WriteUInt32 ($DescriptorBase + 0x320) ([uint32]0x500)
      & $WriteUInt16 ($DescriptorBase + 0x320 + 4) ([uint16]1)
      & $WriteUInt32 ($DescriptorBase + 0x320 + 6) ([uint32]0xB08)
      & $WriteUInt16 ($DescriptorBase + 0x320 + 22) ([uint16]1)
      & $WriteUInt32 ($DescriptorBase + 0x320 + 24) ([uint32]0x360)
      & $WriteUInt32 ($DescriptorBase + 0x360) ([uint32]0x370)
      & $WriteUInt32 ($DescriptorBase + 0x370) ([uint32]0x570)
      & $WriteUInt16 ($DescriptorBase + 0x370 + 8) ([uint16]1)
      & $WriteUInt32 ($DescriptorBase + 0x370 + 10) ([uint32]0x380)
      & $WriteUInt32 ($DescriptorBase + 0x380) ([uint32]0x390)
      & $WriteUInt32 ($DescriptorBase + 0x390) ([uint32]0x5B0)
      & $WriteUInt16 ($DescriptorBase + 0x390 + 4) ([uint16]1)
      & $WriteUInt32 ($DescriptorBase + 0x390 + 6) ([uint32]0x5D0)
      & $WriteString 0x500 '11111111-2222-3333-4444-555555555555:<Default>'
      & $WriteString 0x570 'Software\Dumplings\Media'
      & $WriteString 0x5B0 'DisplayName'
      & $WriteString 0x5D0 'Dumplings Media App'
    }

    # Shell-object directory entry 2 contains one folder and packed shortcut.
    & $WriteUInt32 ($DescriptorBase + 0x27E) ([uint32]0x400)
    & $WriteUInt16 ($DescriptorBase + 0x400 - 2) ([uint16]8)
    & $WriteUInt32 ($DescriptorBase + 0x400 + 8) ([uint32]0x430)
    & $WriteUInt16 ($DescriptorBase + 0x430 + 8) ([uint16]1)
    & $WriteUInt32 ($DescriptorBase + 0x430 + 10) ([uint32]0x450)
    & $WriteUInt32 ($DescriptorBase + 0x450) ([uint32]0x460)
    & $WriteUInt32 ($DescriptorBase + 0x460) ([uint32]0x620)
    & $WriteUInt32 ($DescriptorBase + 0x460 + 4) ([uint32]0x650)
    & $WriteUInt16 ($DescriptorBase + 0x460 + 14) ([uint16]1)
    & $WriteUInt32 ($DescriptorBase + 0x460 + 16) ([uint32]0x490)
    & $WriteUInt32 ($DescriptorBase + 0x490) ([uint32]0x4A0)
    & $WriteUInt32 ($DescriptorBase + 0x4A0) ([uint32]0x680)
    & $WriteUInt32 ($DescriptorBase + 0x4A0 + 4) ([uint32]0x6B0)
    & $WriteUInt32 ($DescriptorBase + 0x4A0 + 10) ([uint32]0x700)
    & $WriteUInt32 ($DescriptorBase + 0x4A0 + 15) ([uint32]0x750)
    & $WriteUInt32 ($DescriptorBase + 0x4A0 + 19) ([uint32]0x770)
    & $WriteUInt32 ($DescriptorBase + 0x4A0 + 23) ([uint32]0x7D0)
    & $WriteUInt32 ($DescriptorBase + 0x4A0 + 27) ([uint32]3)
    & $WriteUInt32 ($DescriptorBase + 0x4A0 + 50) ([uint32]0x790)
    & $WriteString 0x620 'Dumplings Folder'
    & $WriteString 0x650 'FOLDER_NAME'
    & $WriteString 0x680 'Dumplings Shortcut'
    & $WriteString 0x6B0 'Dumplings Visible Shortcut'
    & $WriteString 0x700 '<TARGETDIR>\Dumplings.exe'
    & $WriteString 0x750 '--silent'
    & $WriteString 0x770 '<TARGETDIR>'
    & $WriteString 0x790 'Main Component'
    & $WriteString 0x7D0 'HotKeyCode=4660'

    # One file group (project Component), one cabinet component (feature
    # path), and one setup type prove the source-backed selection topology.
    & $WriteUInt32 ($DescriptorBase + 0x3E) ([uint32]0xA00)
    & $WriteUInt32 ($DescriptorBase + 0xA00) ([uint32]0xB20)
    & $WriteUInt32 ($DescriptorBase + 0xA00 + 4) ([uint32]0xA20)
    & $WriteUInt32 ($DescriptorBase + 0xA20) ([uint32]0xB20)
    & $WriteUInt32 ($DescriptorBase + 0xA20 + 0x16) ([uint32]::MaxValue)
    & $WriteUInt32 ($DescriptorBase + 0xA20 + 0x1A) ([uint32]::MaxValue)
    & $WriteUInt32 ($DescriptorBase + 0x15A) ([uint32]0xA40)
    & $WriteUInt32 ($DescriptorBase + 0xA40) ([uint32]0xB50)
    & $WriteUInt32 ($DescriptorBase + 0xA40 + 4) ([uint32]0xA60)
    & $WriteUInt32 ($DescriptorBase + 0xA60) ([uint32]0xB50)
    & $WriteUInt16 ($DescriptorBase + 0xA60 + 0x6F) ([uint16]1)
    & $WriteUInt32 ($DescriptorBase + 0xA60 + 0x71) ([uint32]0xB00)
    & $WriteUInt32 ($DescriptorBase + 0xB00) ([uint32]0xB20)
    & $WriteUInt32 ($DescriptorBase + 0xB08) ([uint32]0xB20)
    & $WriteUInt16 ($DescriptorBase + 0x30) ([uint16]1)
    & $WriteUInt32 ($DescriptorBase + 0x32) ([uint32]0xAD8)
    & $WriteUInt32 ($DescriptorBase + 0xAD8) ([uint32]1033)
    & $WriteUInt16 ($DescriptorBase + 0xAD8 + 4) ([uint16]1)
    & $WriteUInt32 ($DescriptorBase + 0xAD8 + 8) ([uint32]0xAE4)
    & $WriteUInt32 ($DescriptorBase + 0xAE4) ([uint32]0xAE8)
    & $WriteUInt32 ($DescriptorBase + 0xAE8) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAE8 + 4) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAE8 + 8) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAE8 + 12) ([uint32]1)
    & $WriteUInt32 ($DescriptorBase + 0xAE8 + 16) ([uint32]0xB04)
    & $WriteUInt32 ($DescriptorBase + 0xB04) ([uint32]0xB50)
    & $WriteString 0xB20 'Main Component'
    & $WriteString 0xB50 '<Data>\Main'
    & $WriteString 0xB70 'Complete'
    [IO.File]::WriteAllBytes($Path, $Bytes)
  }

  function New-TestInstallShieldRegistryTypeHeader {
    param ([Parameter(Mandatory)][string]$Path)

    New-TestInstallShieldMediaHeader -Path $Path
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $DescriptorBase = 0x20
    $WriteUInt16 = { param([int]$Offset, [uint16]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt32 = { param([int]$Offset, [uint32]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteString = {
      param([uint32]$RelativeOffset, [string]$Value)
      [Text.Encoding]::Unicode.GetBytes($Value + [char]0).CopyTo($Bytes, $DescriptorBase + $RelativeOffset)
    }

    & $WriteUInt16 ($DescriptorBase + 0x370 + 8) ([uint16]5)
    foreach ($Pair in @(
        @{ Table = 0x380; Record = 0x3A0; Name = 0x800; Data = 0x820; Type = 1; NameText = 'String'; DataText = 'Text' }
        @{ Table = 0x384; Record = 0x3B0; Name = 0x840; Data = 0x860; Type = 2; NameText = 'Expand'; DataText = '%PATH%' }
        @{ Table = 0x388; Record = 0x3C0; Name = 0x880; Data = 0x8A0; Type = 3; NameText = 'Binary'; DataText = '0102A5FF' }
        @{ Table = 0x38C; Record = 0x3D0; Name = 0x8C0; Data = 0x8E0; Type = 4; NameText = 'Dword'; DataText = '123456789' }
        @{ Table = 0x390; Record = 0x3E0; Name = 0x900; Data = 0x920; Type = 7; NameText = 'Multi'; DataText = '004600690072007300740000005300650063006F006E006400000000' }
      )) {
      & $WriteUInt32 ($DescriptorBase + $Pair.Table) ([uint32]$Pair.Record)
      & $WriteUInt32 ($DescriptorBase + $Pair.Record) ([uint32]$Pair.Name)
      & $WriteUInt16 ($DescriptorBase + $Pair.Record + 4) ([uint16]$Pair.Type)
      & $WriteUInt32 ($DescriptorBase + $Pair.Record + 6) ([uint32]$Pair.Data)
      & $WriteString $Pair.Name $Pair.NameText
      & $WriteString $Pair.Data $Pair.DataText
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)
  }
}

Describe 'InstallScript structural header classification' {
  It 'classifies each source-backed compiled-script header family' {
    $Cases = [ordered]@{
      OBS       = [byte[]](0x48, 0x4F, 0xF3, 0xC9)
      aLuZ      = [Text.Encoding]::ASCII.GetBytes('aLuZ')
      kUtZ      = [Text.Encoding]::ASCII.GetBytes('kUtZ')
      OBL       = [Text.Encoding]::ASCII.GetBytes('pOdA')
      'INS-Old' = [byte[]](0xB8, 0xC9, 0x0C, 0x00)
    }
    foreach ($Case in $Cases.GetEnumerator()) {
      $Path = Join-Path $TestDrive "$($Case.Key).bin"
      [IO.File]::WriteAllBytes($Path, $Case.Value + [byte[]]::new(128))
      $Info = Get-InstallShieldInstallScriptHeaderInfo -Path $Path
      $Info.HeaderKind | Should -Be $Case.Key
      $Info.SupportStatus | Should -Be 'Supported'
    }
  }

  It 'decodes the old INS event and action stream into the bounded IR' {
    $Path = Join-Path $TestDrive 'legacy.ins'
    [IO.File]::WriteAllBytes($Path, (New-TestLegacyInstallScriptBytes))

    $Program = Read-InstallShieldInstallScriptProgram -Path $Path

    $Program.FormatProfile | Should -Be 'INS-Old'
    $Program.Functions.Name | Should -Contain 'program'
    $Program.InstructionCount | Should -Be 2
    $Program.Functions[0].Instructions[0].SourceOpcode | Should -Be 0x13
    $Program.Functions[0].Instructions[0].Opcode | Should -Be 0x06
    $Program.Functions[0].Instructions[0].Destination.IntegerValue | Should -Be 1
    $Program.Functions[0].Instructions[0].Operands[0].IntegerValue | Should -Be 7
    $Program.Warnings | Should -BeNullOrEmpty
  }

  It 'decodes an OBS object module through its independent table layout' {
    $Path = Join-Path $TestDrive 'synthetic.obs'
    [IO.File]::WriteAllBytes($Path, (New-TestInstallScriptObjectModuleBytes))

    $Program = Read-InstallShieldInstallScriptProgram -Path $Path
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path

    $Program.FormatProfile | Should -Be 'OBS Object Module'
    $Program.CompilerVersion | Should -Be 'v3.99.002'
    $Program.ExternalSymbols.Name | Should -Be 'EXTERNAL_STRING'
    $Program.AddressResolutions | Should -HaveCount 1
    $Program.Functions | Should -HaveCount 1
    $Program.Functions[0].Name | Should -Be 'program'
    $Program.Functions[0].IsExported | Should -BeTrue
    $Program.Functions[0].BodyDecoded | Should -BeTrue
    $Program.InstructionCount | Should -Be 3
    $Program.Functions[0].Instructions[1].SourceOpcode | Should -Be 0x01
    $Program.Functions[0].Instructions[1].Opcode | Should -Be 0x27
    $Program.Functions[0].Instructions[1].Operation | Should -Be 'Nop'
    $Program.Functions[0].Instructions[1].BranchTarget | Should -Be -1
    $Program.Warnings | Should -BeNullOrEmpty
    $Analysis.ExternalSymbols.Name | Should -Be 'EXTERNAL_STRING'
    $Analysis.ExportedFunctions | Should -Be 'program'
    $Analysis.ParserVersionInfo.BytecodeProfile | Should -Be 'OBS Object Module'
    $Analysis.ParserVersionInfo.CompilerVersion | Should -Be 'v3.99.002'
    $Analysis.ParserVersionInfo.ExternalSymbolCount | Should -Be 1
    $Analysis.ParserVersionInfo.AddressResolutionCount | Should -Be 1
  }

  It 'keeps a malformed OBS action inside its declared basic-block range' {
    $Path = Join-Path $TestDrive 'cross-block.obs'
    $Bytes = New-TestInstallScriptObjectModuleBytes
    $BlockTableOffset = [BitConverter]::ToUInt32($Bytes, 0xD8)
    $FirstBlockOffset = [BitConverter]::ToUInt32($Bytes, $BlockTableOffset)
    [BitConverter]::GetBytes([uint16]4).CopyTo($Bytes, $FirstBlockOffset)
    [IO.File]::WriteAllBytes($Path, $Bytes)

    $Program = Read-InstallShieldInstallScriptProgram -Path $Path

    $Program.Functions[0].BodyDecoded | Should -BeFalse
    $Program.Warnings -join ' ' | Should -Match 'record is truncated'
  }

  It 'catalogues OBL members and selects one embedded program for analysis' {
    $Path = Join-Path $TestDrive 'library.obl'
    New-TestInstallScriptLibrary -Path $Path

    $Library = Get-InstallShieldInstallScriptLibraryInfo -Path $Path
    $Program = Read-InstallShieldInstallScriptProgram -Path $Path
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -LibraryMemberName 'legacy.ins'

    $Library.MemberCount | Should -Be 2
    $Library.Members.Name | Should -Be @('legacy.ins', 'opaque.bin')
    $Library.Members.FormatProfile | Should -Be @('INS-Old', 'Unknown')
    $Program.LibraryMemberName | Should -Be 'legacy.ins'
    $Program.FormatProfile | Should -Be 'INS-Old'
    $Analysis.ParserVersionInfo.HeaderKind | Should -Be 'OBL'
    $Analysis.ParserVersionInfo.Format | Should -Be 'INS-Old'
    $Analysis.ParserVersionInfo.LibraryMemberName | Should -Be 'legacy.ins'
    $Analysis.ParserVersionInfo.LibraryMemberCount | Should -Be 2
  }

  It 'rejects an OBL member range that overlaps its catalog' {
    $Path = Join-Path $TestDrive 'overlap.obl'
    New-TestInstallScriptLibrary -Path $Path
    $Bytes = [IO.File]::ReadAllBytes($Path)
    [BitConverter]::GetBytes([uint32]0).CopyTo($Bytes, 24)
    [IO.File]::WriteAllBytes($Path, $Bytes)

    { Get-InstallShieldInstallScriptLibraryInfo -Path $Path } | Should -Throw '*overlaps the catalog*'
  }

  It 'decodes official 11.5 and 2026 builder OBS libraries when cached' {
    $Cases = @(
      [pscustomobject]@{
        Generation   = '11.5'
        Path         = Join-Path $Script:InstallShieldFixtureDirectory 'BuilderReference\11.5\Libraries\IFX.obl'
        Sha256       = '800A653905220939DF0285DC975D06B9157A9140147DA617F822638503EECFD0'
        Functions    = 913
        Externals    = 118
        Resolutions  = 473
        Instructions = 1005
      }
      [pscustomobject]@{
        Generation   = '2026 R1'
        Path         = Join-Path $Script:InstallShieldFixtureDirectory 'BuilderReference\2026R1\Libraries\IFX.obl'
        Sha256       = 'C22BEE4E70454071729616A86B0A3F4BECD1E75C8C3E8F302D196D3BD0E8C002'
        Functions    = 1156
        Externals    = 166
        Resolutions  = 533
        Instructions = 1088
      }
    )
    if (@($Cases | Where-Object { -not (Test-Path -LiteralPath $_.Path -PathType Leaf) })) {
      Set-ItResult -Skipped -Because 'The official InstallShield builder OBL fixtures are unavailable.'
      return
    }

    foreach ($Case in $Cases) {
      Get-DumplingsTestFixtureHash -Path $Case.Path | Should -Be $Case.Sha256
      $Library = Get-InstallShieldInstallScriptLibraryInfo -Path $Case.Path
      $Program = Read-InstallShieldInstallScriptProgram -Path $Case.Path -LibraryMemberName 'EventsSetup.obs'

      $Library.Members.Name | Should -Be @('EventsPriv.obs', 'EventsSetup.obs', 'EventsSetupPriv.obs', 'PersistPropertyBag.obs')
      $Program.FormatProfile | Should -Be 'OBS Object Module'
      $Program.CompilerVersion | Should -Be 'v3.99.002'
      $Program.Functions | Should -HaveCount $Case.Functions
      $Program.ExternalSymbols | Should -HaveCount $Case.Externals
      $Program.AddressResolutions | Should -HaveCount $Case.Resolutions
      $Program.InstructionCount | Should -Be $Case.Instructions
      $Program.Warnings | Should -BeNullOrEmpty
    }
  }

  It 'classifies a scrambled kUtZ header without mutating the source bytes' {
    $Decoded = [Text.Encoding]::ASCII.GetBytes('kUtZ' + ([string][char]0 * 124))
    $Encoded = [byte[]]::new($Decoded.Length)
    for ($Index = 0; $Index -lt $Decoded.Length; $Index++) {
      $Value = ($Decoded[$Index] + ($Index % 71)) -band 0xFF
      $Encoded[$Index] = [byte](((($Value -shl 2) -bor ($Value -shr 6)) -band 0xFF) -bxor 0xF1)
    }
    $Path = Join-Path $TestDrive 'scrambled-kutz.inx'
    [IO.File]::WriteAllBytes($Path, $Encoded)

    $Info = Get-InstallShieldInstallScriptHeaderInfo -Path $Path

    $Info.HeaderKind | Should -Be 'kUtZ'
    $Info.WasScrambled | Should -BeTrue
    [IO.File]::ReadAllBytes($Path) | Should -Be $Encoded
  }
}

Describe 'InstallShield InstallScript static analysis' {
  It 'decodes a scrambled INX and identifies the external response-file contract' {
    $Path = Join-Path $TestDrive 'setup.inx'
    New-TestInstallScriptFile -Path $Path -Scrambled -String @('program', 'SdWelcome', 'FeatureTransferData', 'setup.iss')

    $Info = Invoke-InstallShieldInstallScriptAnalysis -Path $Path

    $Info.SilentSupport | Should -Be 'ResponseFileRequired'
    $Info.ResponseFileRequirement | Should -Be 'External'
    $Info.DialogCalls | Should -Contain 'SdWelcome'
    $Info.InstallOperations | Should -Contain 'FeatureTransferData'
    $Info.ParserVersionInfo.WasScrambled | Should -BeTrue
    $Info.SilentSwitches | Should -BeNullOrEmpty
  }

  It 'accepts a valid embedded default response file as self-contained silent evidence' {
    $Path = Join-Path $TestDrive 'setup.inx'
    $ResponsePath = Join-Path $TestDrive 'setup.iss'
    New-TestInstallScriptFile -Path $Path -String @('program', 'SdWelcome')
    @'
[InstallShield Silent]
Version=v7.00
File=Response File
[{11111111-1111-1111-1111-111111111111}-DlgOrder]
Dlg0={11111111-1111-1111-1111-111111111111}-SdWelcome-0
Count=1
[{11111111-1111-1111-1111-111111111111}-SdWelcome-0]
Result=1
'@ | Set-Content -LiteralPath $ResponsePath

    $Info = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -EmbeddedResponseFile $ResponsePath

    $Info.SilentSupport | Should -Be 'Supported'
    $Info.ResponseFileRequirement | Should -Be 'Embedded'
    $Info.SilentSwitches | Should -Be '/s'
    $Info.EmbeddedResponseFile.DialogCount | Should -Be 1
  }

  It 'scopes embedded custom-action analysis without applying standalone response-file rules' {
    $Path = Join-Path $TestDrive 'setup.inx'
    New-TestInstallScriptFile -Path $Path -String @('ConfigureProduct', 'SdWelcome', 'setup.iss')

    $Info = Invoke-InstallShieldInstallScriptAnalysis -Path $Path `
      -EntryPoint ConfigureProduct -AnalysisScope EmbeddedAction

    $Info.InstallEntryPoints | Should -Be 'ConfigureProduct'
    $Info.SilentSupport | Should -Be 'NotApplicable'
    $Info.ResponseFileRequirement | Should -Be 'None'
    $Info.SilentSwitches | Should -BeNullOrEmpty
    $Info.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
    $Info.Warnings | Should -Not -Contain 'The compiled script uses InstallShield response-backed dialog support but the media does not ship a valid default setup.iss.'
  }

  It 'reconstructs documented MaintenanceStart ARP defaults without using response metadata as version evidence' {
    $Path = Join-Path $TestDrive 'setup.inx'
    $ResponsePath = Join-Path $TestDrive 'setup.iss'
    New-TestInstallScriptFile -Path $Path -String @(
      'program', 'OnMoveData', 'MaintenanceStart', 'ProductGuid', 'DisplayName', 'DisplayVersion', 'Publisher',
      'Software\Microsoft\Windows\CurrentVersion\Uninstall\'
    )
    @'
[InstallShield Silent]
Version=v7.00
File=Response File
[Application]
Name=Stale response name
Version=0.0.1
Company=Stale response publisher
'@ | Set-Content -LiteralPath $ResponsePath
    $Installer = [pscustomobject]@{
      HasInstallScript   = $true
      InxFiles           = @($Path)
      SetupConfiguration = [ordered]@{
        Startup = [ordered]@{
          Product     = 'Contoso Editor'
          ProductGUID = '11111111-2222-3333-4444-555555555555'
          CompanyName = 'Contoso, Ltd.'
        }
      }
    }

    $Info = Get-InstallShieldInstallScriptInfo -Installer $Installer

    $Info.ProductCode | Should -Be '{11111111-2222-3333-4444-555555555555}'
    $Info.ProjectProductCode | Should -Be $Info.ProductCode
    $Info.CompiledScriptPath | Should -Be $Path
    $Info.DisplayName | Should -Be 'Contoso Editor'
    $Info.Publisher | Should -Be 'Contoso, Ltd.'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesProductCode | Should -Be $Info.ProductCode
    $Info.AppsAndFeaturesInstallerType | Should -Be 'exe'
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Contoso Editor'
    $Info.RegistryWrites.Name | Should -Contain 'ProductGuid'
    $Info.RegistryWrites.Name | Should -Contain 'DisplayName'
    $Info.RegistryWrites.Name | Should -Contain 'Publisher'
    $Info.UnresolvedFields | Should -Contain 'DisplayVersion'
    $Info.UnresolvedFields | Should -Contain 'Scope'
    $Info.UnresolvedFields | Should -Contain 'DefaultInstallLocation'
  }

  It 'applies complete RegDBSetItem overrides and excludes hidden built-in uninstall entries' {
    $Installer = [pscustomobject]@{
      SetupConfiguration = [ordered]@{
        Startup = [ordered]@{
          Product     = 'Project default'
          ProductGUID = '11111111-2222-3333-4444-555555555555'
          CompanyName = 'Project publisher'
        }
      }
    }
    $BaseAnalysis = [ordered]@{
      ArpRuntimeEvidence = @('MaintenanceStart', 'Software\Microsoft\Windows\CurrentVersion\Uninstall\')
      RegistryWrites     = @()
      RegistryItems      = @(
        [pscustomobject]@{ Complete = $true; Name = 'DisplayName'; Data = 'Configured product' }
        [pscustomobject]@{ Complete = $true; Name = 'DisplayVersion'; Data = '2.5.1' }
        [pscustomobject]@{ Complete = $true; Name = 'Publisher'; Data = 'Configured publisher' }
        [pscustomobject]@{ Complete = $true; Name = 'InstallLocation'; Data = 'C:\Program Files\Configured' }
        [pscustomobject]@{ Complete = $true; Name = 'UninstallString'; Data = 'C:\Program Files\Configured\uninstall.exe' }
        [pscustomobject]@{ Complete = $true; Name = 'DisplayIcon'; Data = 'C:\Program Files\Configured\app.exe,0' }
        [pscustomobject]@{ Complete = $true; Name = 'UrlInfoAbout'; Data = 'https://example.test/product' }
        [pscustomobject]@{ Complete = $true; Name = 'HelpLink'; Data = 'https://example.test/support' }
      )
    }

    $Visible = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis ([pscustomobject]$BaseAnalysis)

    $Visible.DisplayName | Should -Be 'Configured product'
    $Visible.DisplayVersion | Should -Be '2.5.1'
    $Visible.Publisher | Should -Be 'Configured publisher'
    $Visible.DefaultInstallLocation | Should -Be 'C:\Program Files\Configured'
    $Visible.UninstallString | Should -Be 'C:\Program Files\Configured\uninstall.exe'
    $Visible.DisplayIcon | Should -Be 'C:\Program Files\Configured\app.exe,0'
    $Visible.URLInfoAbout | Should -Be 'https://example.test/product'
    $Visible.HelpLink | Should -Be 'https://example.test/support'
    $Visible.WritesAppsAndFeaturesEntry | Should -BeTrue

    $BaseAnalysis.RegistryItems += [pscustomobject]@{ Complete = $true; Name = 'SystemComponent'; Data = '1' }
    $Hidden = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis ([pscustomobject]$BaseAnalysis)

    $Hidden.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Hidden.ProductCode | Should -BeNullOrEmpty
    $Hidden.UninstallString | Should -BeNullOrEmpty
    $Hidden.DisplayIcon | Should -BeNullOrEmpty
    $Hidden.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $Hidden.Warnings -join ' ' | Should -Match 'SystemComponent=1'
  }

  It 'preserves registry-only metadata from an explicit visible uninstall entry' {
    $Installer = [pscustomobject]@{ SetupConfiguration = [ordered]@{} }
    $Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Contoso.Editor'
    $RegistryValues = [ordered]@{
      DisplayName          = 'Contoso Editor'
      DisplayVersion       = '3.2.1'
      Publisher            = 'Contoso'
      InstallLocation      = 'C:\Program Files\Contoso Editor'
      UninstallString      = 'C:\Program Files\Contoso Editor\uninstall.exe'
      QuietUninstallString = 'C:\Program Files\Contoso Editor\uninstall.exe /s'
      DisplayIcon          = 'C:\Program Files\Contoso Editor\editor.exe,0'
      URLInfoAbout         = 'https://example.test/editor'
      HelpLink             = 'https://example.test/editor/help'
    }
    $Writes = foreach ($Value in $RegistryValues.GetEnumerator()) {
      [pscustomobject]@{
        Complete = $true
        Root     = 'HKLM'
        Key      = $Key
        Name     = $Value.Key
        Type     = 'REG_SZ'
        Data     = $Value.Value
      }
    }
    $Analysis = [pscustomobject]@{
      ArpRuntimeEvidence = @()
      RegistryWrites     = @($Writes)
      RegistryItems      = @()
    }

    $Info = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis $Analysis

    $Info.ProductCode | Should -Be 'Contoso.Editor'
    $Info.Scope | Should -Be 'machine'
    $Info.UninstallString | Should -Be 'C:\Program Files\Contoso Editor\uninstall.exe'
    $Info.QuietUninstallString | Should -Be 'C:\Program Files\Contoso Editor\uninstall.exe /s'
    $Info.DisplayIcon | Should -Be 'C:\Program Files\Contoso Editor\editor.exe,0'
    $Info.URLInfoAbout | Should -Be 'https://example.test/editor'
    $Info.HelpLink | Should -Be 'https://example.test/editor/help'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'UninstallString'
  }

  It 'keeps HKEY_USER_SELECTABLE uninstall entries while leaving scope unresolved' {
    $Analysis = [pscustomobject]@{
      ArpRuntimeEvidence = @()
      RegistryItems      = @()
      RegistryWrites     = @(
        [pscustomobject]@{ Complete = $true; Root = 'SHCTX'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Dumplings.App'; Name = 'DisplayName'; Type = 'REG_SZ'; Data = 'Dumplings App' }
      )
    }

    $Info = Get-InstallShieldInstallScriptArpInfo -Installer ([pscustomobject]@{ SetupConfiguration = [ordered]@{} }) -Analysis $Analysis

    $Info.ProductCode | Should -Be 'Dumplings.App'
    $Info.DisplayName | Should -Be 'Dumplings App'
    $Info.Scope | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'Scope'
  }

  It 'rejects malformed ProductGUID metadata instead of inventing an uninstall key' {
    $Path = Join-Path $TestDrive 'malformed-guid.inx'
    New-TestInstallScriptFile -Path $Path -String @('MaintenanceStart', 'Software\Microsoft\Windows\CurrentVersion\Uninstall\')
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path
    $Installer = [pscustomobject]@{
      SetupConfiguration = [ordered]@{ Startup = [ordered]@{ Product = 'Contoso'; ProductGUID = 'not-a-guid' } }
    }

    $ArpInfo = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis $Analysis

    $ArpInfo.ProductCode | Should -BeNullOrEmpty
    $ArpInfo.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $ArpInfo.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $ArpInfo.Warnings | Should -Contain "Setup.ini ProductGUID 'not-a-guid' is not a valid GUID and is not used as ProductCode evidence."
  }

  It 'keeps project identity separate when compiled ARP registration evidence is absent' {
    $Path = Join-Path $TestDrive 'no-registration.inx'
    New-TestInstallScriptFile -Path $Path -String @('program', 'FeatureTransferData')
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path
    $Installer = [pscustomobject]@{
      SetupConfiguration = [ordered]@{
        Startup = [ordered]@{
          Product     = 'Contoso Portable Tool'
          ProductGUID = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
          CompanyName = 'Contoso'
        }
      }
    }

    $ArpInfo = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis $Analysis

    $ArpInfo.ProjectProductCode | Should -Be '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
    $ArpInfo.ProjectName | Should -Be 'Contoso Portable Tool'
    $ArpInfo.ProductCode | Should -BeNullOrEmpty
    $ArpInfo.DisplayName | Should -BeNullOrEmpty
    $ArpInfo.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $ArpInfo.AppsAndFeaturesEntries | Should -BeNullOrEmpty
  }

  It 'rejects malformed and oversized script headers without probing arbitrary strings' {
    $Path = Join-Path $TestDrive 'invalid.inx'
    [IO.File]::WriteAllBytes($Path, [byte[]]::new(128))
    { Invoke-InstallShieldInstallScriptAnalysis -Path $Path } | Should -Throw '*supported decoded or scrambled InstallScript header*'
  }

  It 'rejects proprietary cabinet strings that escape the declared file table' {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\InstallerEvidence.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Cabinet.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $Path = Join-Path $TestDrive 'malformed-data1.hdr'
    $Bytes = [byte[]]::new(72)
    foreach ($Field in @(
        @{ Offset = 0; Value = [uint32]0x28635349 } # ISc(
        @{ Offset = 4; Value = [uint32]0x04000A8C } # Modern version family
        @{ Offset = 12; Value = [uint32]20 }        # Descriptor offset
        @{ Offset = 16; Value = [uint32]48 }        # Descriptor size
        @{ Offset = 32; Value = [uint32]48 }        # File-table offset
        @{ Offset = 40; Value = [uint32]4 }         # File-table size
        @{ Offset = 44; Value = [uint32]4 }         # Mirrored file-table size
        @{ Offset = 48; Value = [uint32]1 }         # Directory count
        @{ Offset = 68; Value = [uint32]8 }         # Escapes four-byte table
      )) {
      [BitConverter]::GetBytes($Field.Value).CopyTo($Bytes, $Field.Offset)
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)

    { [Dumplings.InstallShield.InstallShieldCabinetExtractor]::List($Path) } |
      Should -Throw '*directory name offset is outside*'
  }

  It 'rejects a proprietary cabinet catalog whose object count exceeds parser limits' {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $Path = Join-Path $TestDrive 'oversized-catalog-data1.hdr'
    $Bytes = [byte[]]::new(72)
    foreach ($Field in @(
        @{ Offset = 0; Value = [uint32]0x28635349 }
        @{ Offset = 4; Value = [uint32]0x04000A8C }
        @{ Offset = 12; Value = [uint32]20 }
        @{ Offset = 16; Value = [uint32]48 }
        @{ Offset = 32; Value = [uint32]48 }
        @{ Offset = 40; Value = [uint32]4 }
        @{ Offset = 44; Value = [uint32]4 }
        @{ Offset = 48; Value = [uint32]1 }
        @{ Offset = 60; Value = [uint32]100001 }
      )) {
      [BitConverter]::GetBytes($Field.Value).CopyTo($Bytes, $Field.Offset)
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)

    { [Dumplings.InstallShield.InstallShieldCabinetExtractor]::List($Path) } |
      Should -Throw '*catalog counts exceed parser limits*'
  }

  It 'parses source-backed InstallScript media registry sets and shell objects' {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $Path = Join-Path $TestDrive 'media-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path)

    $Inspection.Entries | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.Warnings | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.RegistrySets | Should -HaveCount 1
    $Inspection.MediaMetadata.RegistrySets[0].Name | Should -Be '<Default>'
    $Inspection.MediaMetadata.FileGroups.Name | Should -Contain 'Main Component'
    $Inspection.MediaMetadata.Components.Name | Should -Contain '<Data>\Main'
    $Inspection.MediaMetadata.SetupTypes | Should -HaveCount 1
    $Inspection.MediaMetadata.SetupTypes[0].Features | Should -Contain '<Data>\Main'
    $Inspection.MediaMetadata.RegistryWrites | Should -HaveCount 1
    $Inspection.MediaMetadata.RegistryWrites[0].Root | Should -Be 'HKLM'
    $Inspection.MediaMetadata.RegistryWrites[0].Key | Should -Be 'Software\Dumplings\Media'
    $Inspection.MediaMetadata.RegistryWrites[0].Data | Should -Be 'Dumplings Media App'
    $Inspection.MediaMetadata.RegistryWrites[0].Features | Should -Contain '<Data>\Main'
    $Inspection.MediaMetadata.RegistryWrites[0].SetupTypes | Should -Contain 'Complete'
    $Inspection.MediaMetadata.Shortcuts | Should -HaveCount 1
    $Inspection.MediaMetadata.Shortcuts[0].Name | Should -Be 'Dumplings Visible Shortcut'
    $Inspection.MediaMetadata.Shortcuts[0].Target | Should -Be '<TARGETDIR>\Dumplings.exe'
    $Inspection.MediaMetadata.Shortcuts[0].Arguments | Should -Be '--silent'
    $Inspection.MediaMetadata.Shortcuts[0].Component | Should -Be 'Main Component'
    $Inspection.MediaMetadata.Shortcuts[0].HotKey | Should -Be 4660
    $Inspection.MediaMetadata.Shortcuts[0].ShowCommand | Should -Be 3
    $Inspection.MediaMetadata.Shortcuts[0].Features | Should -Contain '<Data>\Main'
  }

  It 'parses packed multi-language setup types and flagged registry-key counts' {
    $Path = Join-Path $TestDrive 'media-multilanguage-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $DescriptorBase = 0x20
    $WriteUInt16 = { param([int]$Offset, [uint16]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt32 = { param([int]$Offset, [uint32]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }

    # Multi-language media stores a contiguous LCID array followed by one
    # shared setup-type count and table pointer.
    & $WriteUInt16 ($DescriptorBase + 0x30) ([uint16]2)
    & $WriteUInt32 ($DescriptorBase + 0xAD8) ([uint32]1033)
    & $WriteUInt32 ($DescriptorBase + 0xADC) ([uint32]1041)
    & $WriteUInt32 ($DescriptorBase + 0xAE0) ([uint32]1)
    & $WriteUInt32 ($DescriptorBase + 0xAE4) ([uint32]0xAEC)
    & $WriteUInt32 ($DescriptorBase + 0xAEC) ([uint32]0xAF0)
    & $WriteUInt32 ($DescriptorBase + 0xAF0) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAF4) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAF8) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAFC) ([uint32]1)
    & $WriteUInt32 ($DescriptorBase + 0xB00) ([uint32]0xB04)

    # InstallShield uses the high bit as key-control metadata. It is not part
    # of the 15-bit registry-value count stored in the same field.
    & $WriteUInt16 ($DescriptorBase + 0x370 + 8) ([uint16]0x8001)
    [IO.File]::WriteAllBytes($Path, $Bytes)

    $Metadata = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path).MediaMetadata

    $Metadata.Warnings | Should -BeNullOrEmpty
    $Metadata.SetupTypes | Should -HaveCount 2
    $Metadata.SetupTypes.Language | Should -Contain 1033
    $Metadata.SetupTypes.Language | Should -Contain 1041
    $Metadata.SetupTypes.Name | Should -Not -Contain ''
    $Metadata.RegistryWrites | Should -HaveCount 1
    $Metadata.RegistryWrites[0].Data | Should -Be 'Dumplings Media App'
  }

  It 'decodes source-backed InstallScript media registry value encodings' {
    $Path = Join-Path $TestDrive 'media-registry-types-data1.hdr'
    New-TestInstallShieldRegistryTypeHeader -Path $Path

    $Writes = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path).MediaMetadata.RegistryWrites

    ($Writes | Where-Object Name -EQ 'String').Data | Should -Be 'Text'
    ($Writes | Where-Object Name -EQ 'Expand').Data | Should -Be '%PATH%'
    [byte[]](($Writes | Where-Object Name -EQ 'Binary').Data) | Should -Be ([byte[]](1, 2, 165, 255))
    ($Writes | Where-Object Name -EQ 'Dword').Data | Should -Be ([uint32]123456789)
    [string[]](($Writes | Where-Object Name -EQ 'Multi').Data) | Should -Be @('First', 'Second')
    $Writes.Complete | Should -Not -Contain $false
  }

  It 'keeps an ordinary catalog readable when media extension pointers are malformed' {
    $Path = Join-Path $TestDrive 'malformed-media-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path -MalformedRegistryPointer

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path)

    $Inspection.Entries | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.RegistryWrites | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.Shortcuts | Should -HaveCount 1
    $Inspection.MediaMetadata.Warnings -join ' ' | Should -Match 'registry records are malformed or unsupported'
  }

  It 'rolls back an ungrounded Unicode optional graph without hiding an independent valid graph' {
    $Path = Join-Path $TestDrive 'transactional-major22-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path -RawVersion 0x04000898 -MalformedRegistryPointer

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path)

    $Inspection.MediaMetadata.MajorVersion | Should -Be 22
    $Inspection.MediaMetadata.RegistrySets | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.RegistryWrites | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.Shortcuts | Should -HaveCount 1
    $Inspection.MediaMetadata.Warnings -join ' ' | Should -Not -Match 'registry records are malformed or unsupported'
  }

  It 'promotes only default or statically selected InstallScript media records' {
    $DefaultWrite = [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Default'; Name = 'Value'; Type = 'REG_SZ'; Data = 'Default'; RegistrySet = '<Default>'; IsDefaultSet = $true; Components = @(); Complete = $true }
    $NamedWrite = [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Named'; Name = 'Value'; Type = 'REG_SZ'; Data = 'Named'; RegistrySet = 'Optional Set'; IsDefaultSet = $false; Components = @(); Complete = $true }
    $ComponentWrite = [pscustomobject]@{ Root = 'HKCR'; Key = '.dumplings'; Name = ''; Type = 'REG_SZ'; Data = 'Dumplings.File'; RegistrySet = 'Component Set'; IsDefaultSet = $false; Components = @('Main Component'); Complete = $true }
    $Shortcut = [pscustomobject]@{ Name = 'Dumplings'; Target = '<TARGETDIR>\Dumplings.exe'; Component = ''; Confidence = 'ConditionalMediaRecord' }
    $Installer = [pscustomobject]@{
      InstallShieldCabinetSupport = [pscustomobject]@{
        RegistrySets   = @()
        RegistryWrites = @($DefaultWrite, $NamedWrite, $ComponentWrite)
        ShellFolders   = @()
        Shortcuts      = @($Shortcut)
      }
    }
    $Analysis = [pscustomobject]@{
      StaticCalls               = @()
      RegistryWrites            = @()
      Shortcuts                 = @()
      Warnings                  = @()
      Protocols                 = @()
      FileExtensions            = @()
      ProtocolAssociations      = @()
      FileExtensionAssociations = @()
      RegistryAssociationInfo   = $null
    }
    $Module = Get-Module InstallShieldInstallScript

    $Conditional = & $Module { param($Installer, $Analysis) Merge-InstallShieldInstallScriptMediaEvidence -Installer $Installer -Analysis $Analysis } $Installer $Analysis

    $Conditional.RegistryWrites.Key | Should -Be 'Software\Default'
    $Conditional.ConditionalMediaRegistryWrites.Key | Should -Be @('Software\Named', '.dumplings')
    ($Conditional.ConditionalMediaRegistryWrites | Where-Object Key -EQ '.dumplings').Confidence | Should -Be 'ComponentTransfer'
    $Conditional.Shortcuts | Should -BeNullOrEmpty

    $Analysis.StaticCalls = @(
      [pscustomobject]@{ Target = 'CreateRegistrySet'; Arguments = @('Optional Set'); Complete = $true }
      [pscustomobject]@{ Target = '_CreateShellObjects'; Arguments = @(''); Complete = $true }
    )
    $Selected = & $Module { param($Installer, $Analysis) Merge-InstallShieldInstallScriptMediaEvidence -Installer $Installer -Analysis $Analysis } $Installer $Analysis

    $Selected.RegistryWrites.Key | Should -Contain 'Software\Named'
    $Selected.ConditionalMediaRegistryWrites.Key | Should -Be '.dumplings'
    $Selected.ConditionalFileExtensions | Should -Contain 'dumplings'
    $Selected.Shortcuts.Name | Should -Contain 'Dumplings'
    $Selected.Shortcuts[0].Confidence | Should -Be 'ReachedMediaShellObjects'
  }

  It 'validates registry and shell layouts built by official InstallShield 2026 R1 when cached' -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\RegistryHKLM4\data1.hdr')) {
    $RegistryPath = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\RegistryHKLM4\data1.hdr'
    $ShellPath = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\ShellOnly4\data1.hdr'

    $Registry = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($RegistryPath).MediaMetadata
    $Shell = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($ShellPath).MediaMetadata

    $Registry.MajorVersion | Should -Be 32
    $Registry.RegistryWrites | Where-Object { $_.Root -eq 'HKLM' -and $_.Key -eq 'SOFTWARE\DumplingsLab\DefaultSet' } | Should -HaveCount 1
    $Registry.RegistryWrites[0].Data | Should -Be 'DumplingsData'
    $Shell.Shortcuts | Should -HaveCount 1
    $Shell.Shortcuts[0].Target | Should -Be '<TARGETDIR>\Sampler.exe'
    $Shell.Shortcuts[0].Arguments | Should -Be '--dumplings'
    $Shell.Shortcuts[0].ShowCommand | Should -Be 1
    $Shell.Shortcuts[0].Features | Should -Contain '<Data>\Main App'
    $Shell.Shortcuts[0].SetupTypes | Should -Contain 'Complete'
    $Registry.Warnings + $Shell.Warnings | Should -BeNullOrEmpty
  }

  It 'validates registry encodings and shortcut fields from official InstallShield 2026 R1 differential media when cached' -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\RegistryTypes6\data1.hdr')) {
    $Root = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential'
    $Registry = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect((Join-Path $Root 'RegistryTypes6\data1.hdr')).MediaMetadata
    $Shell = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect((Join-Path $Root 'ShellFields7\data1.hdr')).MediaMetadata

    [byte[]](($Registry.RegistryWrites | Where-Object Name -EQ 'BinaryValue').Data) | Should -Be ([byte[]](1, 2, 165, 255))
    ($Registry.RegistryWrites | Where-Object Name -EQ 'DwordValue').Data | Should -Be ([uint32]123456789)
    [string[]](($Registry.RegistryWrites | Where-Object Name -EQ 'MultiValue').Data) | Should -Be @('First', 'Second')
    $Shell.Shortcuts[0].HotKey | Should -Be 4660
    $Shell.Shortcuts[0].ShowCommand | Should -Be 3
    $Shell.Shortcuts[0].Features | Should -Contain '<Data>\Main App'
    $Shell.Shortcuts[0].SetupTypes | Should -Contain 'Complete'
    $Registry.Warnings + $Shell.Warnings | Should -BeNullOrEmpty
  }

  It 'preserves InstallScript 11.5 structure references across function frames' {
    $Path = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\Legacy115\PointerSemantics\PointerRegistry.inx'
    if (-not (Test-Path -LiteralPath $Path)) {
      Set-ItResult -Skipped -Because 'the controlled InstallShield 11.5 pointer fixture is not cached'
      return
    }

    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -EntryPoint 'PointerEvidence'
    $Write = $Analysis.RegistryWrites | Where-Object Name -EQ 'PointerValue'
    $Call = $Analysis.StaticCalls | Where-Object { $_.Function -eq 'PointerEvidence' -and $_.Target -match '^function\d+$' } | Select-Object -First 1

    $Call.Arguments | Should -Contain '&record'
    $Write | Should -HaveCount 1
    $Write.Root | Should -Be 'HKLM'
    $Write.Key | Should -Be 'SoftwareDumplings'
    $Write.Data | Should -Be 'DumplingsPointerEvidence'
    $Write.Complete | Should -BeTrue
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x001A | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x001C | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
  }

  It 'writes InstallScript 11.5 BYREF primitive parameters back to their caller' {
    $Path = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\Legacy115\IndirectionSemantics\ByRef.inx'
    if (-not (Test-Path -LiteralPath $Path)) {
      Set-ItResult -Skipped -Because 'the controlled InstallShield 11.5 BYREF fixture is not cached'
      return
    }

    $Program = Read-InstallShieldInstallScriptProgram -Path $Path
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -EntryPoint 'ByRefEvidence'
    $Write = $Analysis.RegistryWrites | Where-Object Name -EQ 'ByRefValue'

    $Program.Functions[1].ParameterFlags[0] -band 0x02 | Should -Be 0x02
    $Program.Functions[2].ParameterFlags[0] -band 0x02 | Should -Be 0x02
    $Write | Should -HaveCount 1
    $Write.Data | Should -Be 'After'
    $Write.Complete | Should -BeTrue
  }

  It 'dereferences primitive pointers emitted by InstallShield 11.5' {
    $Path = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\Legacy115\IndirectionSemantics\Indirect.inx'
    if (-not (Test-Path -LiteralPath $Path)) {
      Set-ItResult -Skipped -Because 'the controlled InstallShield 11.5 indirection fixture is not cached'
      return
    }

    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -EntryPoint 'IndirectEvidence'
    $Write = $Analysis.RegistryWrites | Where-Object Name -EQ 'IndirectValue'

    $Write | Should -HaveCount 1
    $Write.Data | Should -Be '42'
    $Write.Complete | Should -BeTrue
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x001B | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
  }

  It 'keeps InstallShield 11.5 catch-only effects out of normal-path metadata' {
    $Path = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\Legacy115\ExceptionSemantics\Catch.inx'
    if (-not (Test-Path -LiteralPath $Path)) {
      Set-ItResult -Skipped -Because 'the controlled InstallShield 11.5 exception fixture is not cached'
      return
    }

    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -EntryPoint 'CatchEvidence'

    $Analysis.RegistryWrites.Name | Should -Contain 'NormalPath'
    $Analysis.RegistryWrites.Name | Should -Not -Contain 'CatchPath'
    foreach ($Opcode in 0x0036, 0x0037, 0x0038) {
      $Analysis.OpcodeCoverage | Where-Object Opcode -EQ $Opcode | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
    }
  }

  It 'records InstallShield 11.5 DLL load and unload instructions without loading the module' {
    $Path = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\Legacy115\ScriptSamples\ScriptSamples-Setup.inx'
    if (-not (Test-Path -LiteralPath $Path)) {
      Set-ItResult -Skipped -Because 'the official InstallShield 11.5 ScriptSamples fixture is not cached'
      return
    }

    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -EntryPoint 'DllWrapper'

    $Analysis.DllOperations | Should -HaveCount 2
    $Analysis.DllOperations.Operation | Should -Be @('Load', 'Unload')
    $Analysis.DllOperations.Path | ForEach-Object { $_ | Should -Match 'MyDLL\.Dll$' }
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x0039 | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x003A | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x002F | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x0030 | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
  }

  It 'exposes InstallShield 11.5 property-handler registrations without invoking them' {
    $Path = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\BuilderDifferential\Legacy115\ScenarioSemantics\ScenarioVariables.inx'
    if (-not (Test-Path -LiteralPath $Path)) {
      Set-ItResult -Skipped -Because 'the controlled InstallShield 11.5 scenario-variable fixture is not cached'
      return
    }

    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path
    $Handler = $Analysis.PropertyHandlers | Where-Object {
      $_.Function -eq 'function831' -and $_.VariableKind -eq 'LocalNumberVariable' -and $_.VariableIndex -eq 6
    } | Select-Object -First 1

    $Analysis.PropertyHandlers.Count | Should -BeGreaterOrEqual 40
    $Handler.GetterFunction | Should -Be 'function829'
    $Handler.SetterFunction | Should -Be 'function830'
    $Handler.HandleSlotKind | Should -Be 'LocalNumberVariable'
    $Handler.HandleSlotIndex | Should -Be 119
    $Handler.Complete | Should -BeTrue
    $Analysis.ParserVersionInfo.PropertyHandlerCount | Should -Be $Analysis.PropertyHandlers.Count
    $Analysis.OpcodeCoverage | Where-Object Opcode -EQ 0x003B | Select-Object -ExpandProperty Emulation | Should -Be 'Structural'
  }

  It 'validates the cached Celsys self-contained response layout when available' -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\CSP_504w_setup.exe')) {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $Destination = Join-Path $TestDrive 'Celsys'
    $Info = Get-InstallShieldInfo -Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\CSP_504w_setup.exe' -DestinationPath $Destination

    $Info.Variant | Should -Be 'InstallScript'
    $Info.InstallScriptInfo.SilentSupport | Should -Be 'Supported'
    $Info.InstallScriptInfo.ResponseFileRequirement | Should -Be 'Embedded'
    $Info.InstallScriptInfo.EmbeddedResponseFile.DialogCount | Should -BeGreaterThan 0
    $Info.ProductCode | Should -Be '{1E4572D2-28BC-4BC9-B743-13DC6CFD71DB}'
    $Info.DisplayName | Should -Be 'CLIP STUDIO PAINT'
    $Info.Publisher | Should -Be 'CELSYS'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.InstallScriptInfo.Path | Should -Be 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\CSP_504w_setup.exe'
    $Info.InstallScriptInfo.CompiledScriptName | Should -Be 'setup.inx'
    $Info.InstallScriptInfo.AppsAndFeaturesEntries[0].ProductCode | Should -Be $Info.ProductCode
    $Info.FileExtensions | Should -Contain 'clip'
    $Info.FileExtensions | Should -Contain 'cwp'
    $Info.FileExtensions | Should -HaveCount 10
    $Info.RegistryAssociationInfo.FileExtensions | Should -Be $Info.FileExtensions
    $Info.InstallScriptInfo.ParserVersionInfo.EmulationTruncated | Should -BeFalse
    $Info.InstallScriptInfo.UnsupportedOpcodes | Should -BeNullOrEmpty
  }

  It 'identifies the cached <Name> installer as requiring an external response file' -ForEach @(
    @{ Name = 'DinoCapture 2'; File = 'dnc2_1.5.55_U.exe' }
    @{ Name = 'DinoCapture 3'; File = 'dnc3_1.1.1.6.exe' }
  ) -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\dnc2_1.5.55_U.exe')) {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Join-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield' $File
    if (-not (Test-Path $InstallerPath)) { Set-ItResult -Skipped -Because "$Name fixture is not cached"; return }
    $Info = Get-InstallShieldInfo -Path $InstallerPath -DestinationPath (Join-Path $TestDrive $Name.Replace(' ', '-'))

    $Info.Variant | Should -Be 'InstallScript'
    $Info.InstallScriptInfo.SilentSupport | Should -Be 'ResponseFileRequired'
    $Info.InstallScriptInfo.ResponseFileRequirement | Should -Be 'External'
    $Info.InstallScriptInfo.SilentSwitches | Should -BeNullOrEmpty
    $Info.ProductCode | Should -Be $(if ($Name -eq 'DinoCapture 2') { '{683A259B-BCA2-4161-9B23-2110F2AE472C}' } else { '{3A0AD8A8-7196-43F1-9AB9-2B8CCCBD6051}' })
    $Info.DisplayName | Should -Be $(if ($Name -eq 'DinoCapture 2') { 'DinoCapture 2.0' } else { 'DinoCapture 3.0' })
    $Info.Publisher | Should -Be 'AnMo Electronics Corporation'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.ExecutedPayloads.Operation | Should -Contain 'CreateProcess'
    $Info.ExecutedPayloads.CommandLine -join ' ' | Should -Match 'arch\.bat'
    $Info.InstallScriptInfo.ParserVersionInfo.EmulationTruncated | Should -BeFalse
    $Info.InstallScriptInfo.UnsupportedOpcodes | Should -BeNullOrEmpty
    if ($Name -eq 'DinoCapture 2') {
      # The default media set authors an additional non-GUID uninstall key in
      # both registry views. Preserve that visible ARP evidence without
      # replacing the built-in MaintenanceStart GUID identity.
      $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'DinoCapture 2.0'
      ($Info.AppsAndFeaturesEntries | Where-Object ProductCode -EQ 'DinoCapture 2.0').DisplayVersion | Should -Be '1.5.55'
      $Info.InstallScriptInfo.ArpRegistrationMode | Should -Be 'ExplicitAndMaintenanceDefaults'
    }
  }

  It 'parses the cached Unitronics PackageForTheWeb and Stirling InstallScript generations' -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\U90Ladder_6_6_45.exe')) {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\U90Ladder_6_6_45.exe'
    $Info = Get-InstallShieldInfo -Path $InstallerPath -DestinationPath (Join-Path $TestDrive 'Unitronics')

    $Info.ContainerFormat | Should -Be 'PackageForTheWeb Cabinet'
    $Info.PackageForTheWebCabinet.FileCount | Should -Be 9
    $Info.PackageForTheWebCabinet.Offset + $Info.PackageForTheWebCabinet.Length | Should -Be (Get-Item -LiteralPath $InstallerPath).Length
    $Info.Variant | Should -Be 'InstallScript'
    $Info.HasMsi | Should -BeFalse
    $Info.HasInstallScript | Should -BeTrue
    $Info.ExtractedFiles | ForEach-Object { [IO.Path]::GetFileName($_) } | Should -Contain 'setup.inx'
    $Info.ExtractedFiles | ForEach-Object { [IO.Path]::GetFileName($_) } | Should -Contain 'data1.cab'
    $Info.ExtractedFiles | ForEach-Object { [IO.Path]::GetFileName($_) } | Should -Contain 'data2.cab'
    $Info.InstallScriptInfo.ProjectProductCode | Should -Be '{08E54E42-CF60-4C0F-8856-B70126890BA8}'
    $Info.InstallScriptInfo.ProjectName | Should -Be 'U90Ladder'
    $Info.InstallScriptInfo.ProductCode | Should -BeNullOrEmpty
    $Info.InstallScriptInfo.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $Info.InstallScriptInfo.SilentSupport | Should -Be 'ResponseFileRequired'
    $Info.InstallScriptInfo.ResponseFileRequirement | Should -Be 'External'
    $Info.InstallScriptInfo.ParserVersionInfo.CopyrightMarker | Should -Be 'Copyright (c) 1990-1999 Stirling Technologies, Ltd. All Rights Reserved.'
    $Info.InstallScriptInfo.ParserVersionInfo.FunctionCount | Should -Be 551
    $Info.InstallScriptInfo.ParserVersionInfo.InstructionCount | Should -BeGreaterThan 10000
    $Trace = $Info.InstallScriptInfo.DialogTraces | Where-Object Scenario -EQ 'FreshInstall'
    $Trace.EntryPoint | Should -Be 'program'
    $Trace.Source | Should -Be 'FrameworkCallback'
    $Trace.IsComplete | Should -BeFalse
    $Trace.Dialogs | Should -Be @('SdWelcome', 'SdLicense', 'SdAskDestPath', 'SdSelectFolder', 'SdStartCopy')
    @($Trace.Steps | Where-Object { $_.Alternatives -contains 'SdFinish' -and $_.Alternatives -contains 'SdFinishReboot' }) | Should -HaveCount 1
    $Trace.Warnings -join ' ' | Should -Match 'recorded VM response file'
    $MaintenanceTrace = $Info.InstallScriptInfo.DialogTraces | Where-Object Scenario -EQ 'Maintenance'
    $MaintenanceTrace.Dialogs | Should -Be @('SdWelcomeMaint', 'SdComponentTree')
  }

  It 'extracts only a requested PackageForTheWeb catalog entry' -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\U90Ladder_6_6_45.exe')) {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $Destination = Join-Path $TestDrive 'Unitronics-Selected'

    $Result = Expand-InstallShieldInstaller `
      -Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\U90Ladder_6_6_45.exe' `
      -DestinationPath $Destination `
      -Name 'setup.inx' `
      -CollisionAction Error

    $Result | Should -Be (Get-Item -LiteralPath $Destination).FullName
    $Files = @(Get-ChildItem -LiteralPath $Destination -Recurse -File)
    $Files | Should -HaveCount 1
    $Files[0].Name | Should -Be 'setup.inx'
  }

  It 'recovers the <Architecture> PRONOTE script from proprietary InstallShield cabinet media' -ForEach @(
    @{
      Architecture     = 'x64'
      File             = 'Install_PRNclient_FR_2023.0.1.2_win64.exe'
      ProductCode      = '{02871376-45F6-4642-9D84-C7681ABE361F}'
      DisplayName      = 'Client PRONOTE 2023 - 64bit'
      ScriptSize       = 304235
      FunctionCount    = 883
      InstructionCount = 19437
    }
    @{
      Architecture     = 'x86'
      File             = 'Install_PRNclient_FR_2023.0.1.2_win32.exe'
      ProductCode      = '{6675F0E8-C34B-4FB8-9E61-35EE4C20136F}'
      DisplayName      = 'Client PRONOTE 2023 - 32bit'
      ScriptSize       = 304094
      FunctionCount    = 883
      InstructionCount = 19427
    }
  ) -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\Install_PRNclient_FR_2023.0.1.2_win64.exe')) {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\PE.psm1') -Force
    . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Join-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield' $File
    if (-not (Test-Path -LiteralPath $InstallerPath)) { Set-ItResult -Skipped -Because "$Architecture fixture is not cached"; return }

    $Info = Get-InstallShieldInfo -Path $InstallerPath -DestinationPath (Join-Path $TestDrive "Pronote-$Architecture")

    $Info.Variant | Should -Be 'InstallScript'
    $Info.HasMsi | Should -BeFalse
    $Info.HasInstallScript | Should -BeTrue
    $Info.InstallShieldCabinetSupport.HeaderFiles | Should -HaveCount 1
    $Info.InstallShieldCabinetSupport.CatalogEntryCount | Should -BeGreaterThan 20
    $Info.InstallShieldCabinetSupport.SupportEntries | Should -HaveCount 2
    $Info.InstallShieldCabinetSupport.SupportEntries.Name | Should -Contain 'setup.inx'
    $Info.InstallShieldCabinetSupport.SupportEntries.Name | Should -Contain 'StringTable_0x040c.ips'
    $Info.InstallShieldCabinetSupport.ExpandedBytes | Should -Be ($ScriptSize + 8858)
    $Info.InstallShieldCabinetSupport.Warnings | Should -BeNullOrEmpty
    $Info.ProductCode | Should -Be $ProductCode
    $Info.DisplayName | Should -Be $DisplayName
    $Info.Publisher | Should -Be 'Index Education'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.SilentSupport | Should -Be 'ResponseFileRequired'
    $Info.ResponseFileRequirement | Should -Be 'External'
    $Info.InstallScriptInfo.ParserVersionInfo.WasScrambled | Should -BeTrue
    $Info.InstallScriptInfo.ParserVersionInfo.FunctionCount | Should -Be $FunctionCount
    $Info.InstallScriptInfo.ParserVersionInfo.InstructionCount | Should -Be $InstructionCount
    $Info.InstallScriptInfo.DialogCalls | Should -Contain 'SdFeatureTree'
    $Info.FileExtensions | Should -Contain 'pcprn'
    $Info.RegistryWrites | Where-Object { $_.Root -eq 'HKCR' -and $_.Key -eq '.pcprn' -and $_.Data -eq 'IndexEducation.pcprn' } | Should -HaveCount 1
    $Info.InstallScriptInfo.ParserVersionInfo.EmulationTruncated | Should -BeFalse
    $Info.InstallScriptInfo.UnsupportedOpcodes | Should -BeNullOrEmpty
    $Info.InstallScriptInfo.Warnings -join ' ' | Should -Match 'does not ship a valid fresh-install setup\.iss'
  }

  It 'parses Dell Display and Peripheral Manager multi-language media when cached' {
    Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Join-Path $Script:InstallShieldFixtureDirectory 'Dell\DDPM-Setup_2.3.0.17.exe'
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'the Dell DDPM fixture is not cached'
      return
    }
    Get-DumplingsTestFixtureHash -Path $InstallerPath | Should -Be '8B8FF94FA4B110F4A757DE455CE4D1C8A37FCF165ADB54107BF98F81557A7CC8'
    $Info = Get-InstallShieldInfo -Path $InstallerPath -DestinationPath (Join-Path $TestDrive 'Dell-DDPM')

    $Info.Variant | Should -Be 'InstallScript'
    $Info.ProductCode | Should -Be '{21A24609-08A2-423E-80DE-4D33A933F1A1}'
    $Info.DisplayName | Should -Be 'Dell Display and Peripheral Manager'
    $Info.MediaSetupTypes | Should -HaveCount 34
    $Info.InstallShieldCabinetSupport.RegistryWrites | Should -HaveCount 52
    $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2025'
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Cabinet17/UnicodeCatalog'
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Script/aLuZ'
    $Info.Warnings -join ' ' | Should -Not -Match 'media (?:setup-type|registry) records are malformed or unsupported'
    $Info.InstallScriptInfo.EmbeddedResponseFile.DialogNames | Should -Contain 'SdWelcomeMaint'
    $Info.InstallScriptInfo.Warnings -join ' ' | Should -Match 'does not match the statically reconstructed fresh-install dialog order'
  }

  It 'builds an instruction-backed Celsys dialog trace and validates the embedded response order' -Skip:(-not (Test-Path 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\CSP_504w_setup_u\Disk1\setup.inx')) {
    $ScriptPath = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\CSP_504w_setup_u\Disk1\setup.inx'
    $ResponsePath = 'C:\Users\SpecterShell\Repository\Dumplings-TestFixtures\PackageModule\InstallShield\CSP_504w_setup_u\Disk1\setup.iss'

    $Program = Read-InstallShieldInstallScriptProgram -Path $ScriptPath
    $Trace = Get-InstallShieldInstallScriptDialogTrace -Program $Program | Where-Object Scenario -EQ 'FreshInstall'
    $Validation = Test-InstallShieldResponseFile -Path $ResponsePath -Trace $Trace

    $Program.Functions.Name | Should -Contain 'OnFirstUIBefore'
    $Program.InstructionCount | Should -BeGreaterThan 1000
    $Trace.Dialogs | Should -Be @('SdWelcome', 'LicenseDialog', 'SdAskDestPath2', 'SdStartCopy2')
    @($Trace.Steps | Where-Object { $_.Alternatives -contains 'SdFinish' }).Count | Should -Be 1
    $Validation.IsValid | Should -BeTrue
    $Validation.Response.ProductCode | Should -Be '{1E4572D2-28BC-4BC9-B743-13DC6CFD71DB}'
  }

  It 'creates reviewable response templates without inventing project-specific feature state' {
    $Trace = [pscustomobject]@{
      IsComplete = $false
      Steps      = @(
        [pscustomobject]@{ Offset = 16; Dialog = 'SdWelcome'; Alternatives = @() }
        [pscustomobject]@{ Offset = 32; Dialog = 'SdComponentTree'; Alternatives = @() }
        [pscustomobject]@{ Offset = 48; Dialog = $null; Alternatives = @('SdFinish', 'SdFinishReboot') }
      )
    }

    $Template = New-InstallShieldResponseFileTemplate -Trace $Trace -ProductCode '{11111111-2222-3333-4444-555555555555}'

    $Template.IsComplete | Should -BeFalse
    $Template.Content | Should -Match '\[\{11111111-2222-3333-4444-555555555555\}-DlgOrder\]'
    $Template.Content | Should -Match 'TODO: record this dialog in the validation VM'
    $Template.Content | Should -Match 'choose one of SdFinish, SdFinishReboot'
    $Template.Warnings | Should -Contain "Dialog 'SdComponentTree' contains project-specific feature data that cannot be generated statically."
  }

  It 'reports response dialog-order mismatches without executing Setup.exe' {
    $ResponsePath = Join-Path $TestDrive 'mismatch.iss'
    @'
[InstallShield Silent]
Version=v7.00
File=Response File
[{11111111-2222-3333-4444-555555555555}-DlgOrder]
Dlg0={11111111-2222-3333-4444-555555555555}-SdFinish-0
Count=1
'@ | Set-Content -LiteralPath $ResponsePath
    $Trace = [pscustomobject]@{
      IsComplete = $true
      Dialogs    = @('SdWelcome')
      Steps      = @([pscustomobject]@{ Dialog = 'SdWelcome'; Alternatives = @() })
    }

    $Result = Test-InstallShieldResponseFile -Path $ResponsePath -Trace $Trace

    $Result.IsValid | Should -BeFalse
    $Result.Diagnostics.Id | Should -Contain 'DialogOrderMismatch'
  }
}
