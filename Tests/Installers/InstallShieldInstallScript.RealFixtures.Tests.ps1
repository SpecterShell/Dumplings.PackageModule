. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldInstallScriptTestSetup.ps1')

Describe 'InstallScript response behavior and real fixtures' -Tag 'RealFixture', 'Network' {
  It 'validates the cached Celsys self-contained response layout when available' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CSP_504w_setup.exe')
    if (-not (Test-Path -LiteralPath $InstallerPath)) { Set-ItResult -Skipped -Because 'the Celsys fixture is not cached'; return }
    $Destination = Join-Path $TestDrive 'Celsys'
    $Info = Get-InstallShieldInfo -Path $InstallerPath -DestinationPath $Destination

    $Info.Variant | Should -Be 'InstallScript'
    $Info.InstallScriptInfo.SilentSupport | Should -Be 'Supported'
    $Info.InstallScriptInfo.ResponseFileRequirement | Should -Be 'Embedded'
    $Info.InstallScriptInfo.EmbeddedResponseFile.DialogCount | Should -BeGreaterThan 0
    $Info.ProductCode | Should -Be '{1E4572D2-28BC-4BC9-B743-13DC6CFD71DB}'
    $Info.DisplayName | Should -Be 'CLIP STUDIO PAINT'
    $Info.Publisher | Should -Be 'CELSYS'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.InstallScriptInfo.Path | Should -Be $InstallerPath
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
  ) {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $File)
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

  It 'parses the cached Unitronics PackageForTheWeb and Stirling InstallScript generations' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'U90Ladder_6_6_45.exe')
    if (-not (Test-Path -LiteralPath $InstallerPath)) { Set-ItResult -Skipped -Because 'the Unitronics fixture is not cached'; return }
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

  It 'extracts only a requested PackageForTheWeb catalog entry' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'U90Ladder_6_6_45.exe')
    if (-not (Test-Path -LiteralPath $InstallerPath)) { Set-ItResult -Skipped -Because 'the Unitronics fixture is not cached'; return }
    $Destination = Join-Path $TestDrive 'Unitronics-Selected'

    $Result = Expand-InstallShieldInstaller `
      -Path $InstallerPath `
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
  ) {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $File)
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
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'DDPM-Setup_2.3.0.17.exe')
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

  It 'builds an instruction-backed Celsys dialog trace and validates the embedded response order' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $InstallerPath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CSP_504w_setup.exe')
    if (-not (Test-Path -LiteralPath $InstallerPath)) { Set-ItResult -Skipped -Because 'the Celsys fixture is not cached'; return }

    $Destination = Join-Path $TestDrive 'Celsys-Dialog'
    $null = Expand-InstallShieldInstaller -Path $InstallerPath -DestinationPath $Destination -CollisionAction Error
    $ScriptPath = Get-ChildItem -LiteralPath $Destination -Filter 'setup.inx' -Recurse -File | Select-Object -First 1 -ExpandProperty FullName
    $ResponsePath = Get-ChildItem -LiteralPath $Destination -Filter 'setup.iss' -Recurse -File | Select-Object -First 1 -ExpandProperty FullName
    $ScriptPath | Should -Not -BeNullOrEmpty
    $ResponsePath | Should -Not -BeNullOrEmpty

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
