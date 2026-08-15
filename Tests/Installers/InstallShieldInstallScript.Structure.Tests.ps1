. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldInstallScriptTestSetup.ps1')

Describe 'InstallScript structural formats' -Tag Unit {
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
        Path         = Join-Path $Script:InstallShieldFixtureDirectory '11.5\Reference\Libraries\IFX.obl'
        Sha256       = '800A653905220939DF0285DC975D06B9157A9140147DA617F822638503EECFD0'
        Functions    = 913
        Externals    = 118
        Resolutions  = 473
        Instructions = 1005
      }
      [pscustomobject]@{
        Generation   = '2026 R1'
        Path         = Join-Path $Script:InstallShieldFixtureDirectory '2026R1\Reference\Libraries\IFX.obl'
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
