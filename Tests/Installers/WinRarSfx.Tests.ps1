. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive
  $ProgressPreference = 'SilentlyContinue'

  function Get-BootstrapperFixture {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$Url
    )
    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url
  }
}

Describe 'WinRAR GUI SFX parser' {
  It 'Parses Setup and Presetup commands from the archive comment' {
    $Result = ConvertFrom-WinRarSfxConfiguration -Content "Presetup=prepare.cmd`r`nSetup=setup.exe /w`r`nSilent=2" -ArchiveEntry @('prepare.cmd', 'setup.exe')

    $Result.Commands.Count | Should -Be 2
    $Result.Commands[0].Command.ExecutedPayload | Should -Be 'prepare.cmd'
    $Result.Commands[1].Command.ExecutedPayload | Should -Be 'setup.exe'
    $Result.Commands[1].Command.ArgumentList | Should -Be @('/w')
    $Result.Values.Silent | Should -Be '2'
  }

  It 'Accepts a leading RAR CMT service marker attached to Setup' {
    $Result = ConvertFrom-WinRarSfxConfiguration -Content "CMTSetup=setup.exe /silent`r`nSilent=1" -ArchiveEntry @('setup.exe')

    $Result.Commands.Count | Should -Be 1
    $Result.Commands[0].Stage | Should -Be 'Setup'
    $Result.Commands[0].Command.ExecutedPayload | Should -Be 'setup.exe'
    $Result.Commands[0].Command.ArgumentList | Should -Be @('/silent')
    $Result.Values.PSObject.Properties.Name | Should -Not -Contain 'CMTSetup'
  }

  It 'Reads the configured InstallShield launcher from the SCREENView SFX' {
    $Installer = Get-BootstrapperFixture -Name 'Lakes_SCREENView_4.0.1.exe' -Url 'https://www.weblakes.com/products/screen/update/Lakes_Environmental_SCREEN_View_V.4.0.1_Install.exe'
    $Result = Get-WinRarSfxInfo -Path $Installer

    $Result.Format | Should -Be 'WinRAR GUI SFX (RAR4)'
    $Result.ExecutedPayloads | Should -Contain 'setup.exe'
    $Result.Commands[0].Command.ArgumentList | Should -Contain '/w'
    $Result.NestedFiles | Should -Contain 'Lakes Environmental SCREEN View V.4.0.1.MSI'
  }

  It 'Reads the configured command from an official RAR5 SFX comment' {
    $Installer = Get-BootstrapperFixture -Name 'RARLab_WinRAR_7.23.0_x64.exe' -Url 'https://www.rarlab.com/rar/winrar-x64-723.exe'
    $Result = Get-WinRarSfxInfo -Path $Installer

    $Result.Format | Should -Be 'WinRAR GUI SFX (RAR5)'
    $Result.ExecutedPayloads | Should -Contain 'uninstall.exe'
    $Result.Commands[0].Command.ArgumentList | Should -Contain '/setup'
  }
}
