. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldInstallScriptTestSetup.ps1')

Describe 'InstallScript bytecode and emulation' -Tag Unit {
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
    $Info.Diagnostics.Message | Should -Not -Contain 'The compiled script uses InstallShield response-backed dialog support but the media does not ship a valid default setup.iss.'
  }

  It 'preserves InstallScript 11.5 structure references across function frames' {
    $Path = Join-Path $Script:InstallShieldFixtureDirectory '11.5\Differential\PointerSemantics\PointerRegistry.inx'
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
    $Path = Join-Path $Script:InstallShieldFixtureDirectory '11.5\Differential\IndirectionSemantics\ByRef.inx'
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
    $Path = Join-Path $Script:InstallShieldFixtureDirectory '11.5\Differential\IndirectionSemantics\Indirect.inx'
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
    $Path = Join-Path $Script:InstallShieldFixtureDirectory '11.5\Differential\ExceptionSemantics\Catch.inx'
    if (-not (Test-Path -LiteralPath $Path)) {
      Set-ItResult -Skipped -Because 'the controlled InstallShield 11.5 exception fixture is not cached'
      return
    }

    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path -EntryPoint 'CatchEvidence'

    $Analysis.RegistryWrites.Name | Should -Contain 'NormalPath'
    $Analysis.RegistryWrites.Name | Should -Not -Contain 'CatchPath'
    $Analysis.Diagnostics.Message | Should -Contain 'InstallScript catch-only effects were excluded from normal-path metadata.'
    @($Analysis.Diagnostics | Where-Object Kind -NE Information).Message | Should -Not -Contain 'InstallScript catch-only effects were excluded from normal-path metadata.'
    foreach ($Opcode in 0x0036, 0x0037, 0x0038) {
      $Analysis.OpcodeCoverage | Where-Object Opcode -EQ $Opcode | Select-Object -ExpandProperty Emulation | Should -Be 'Evaluated'
    }
  }

  It 'records InstallShield 11.5 DLL load and unload instructions without loading the module' {
    $Path = Join-Path $Script:InstallShieldFixtureDirectory '11.5\Differential\ScriptSamples\ScriptSamples-Setup.inx'
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
    $Path = Join-Path $Script:InstallShieldFixtureDirectory '11.5\Differential\ScenarioSemantics\ScenarioVariables.inx'
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
}
