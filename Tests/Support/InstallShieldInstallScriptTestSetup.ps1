BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerDiagnostics.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Cabinet.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShieldInstallScript.psm1') -Force
  $Script:InstallShieldFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\InstallShield'

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
