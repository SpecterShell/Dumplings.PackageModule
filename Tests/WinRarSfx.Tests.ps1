BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'General', 'Binary', 'Compression', 'Archive', 'PE', 'Bootstrapper', 'WinRarSfx')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\BootstrapperParsers'
  $ProgressPreference = 'SilentlyContinue'

  function Get-BootstrapperFixture {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$Url
    )
    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
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

  It 'Reads the configured InstallShield launcher from the SCREENView SFX' {
    $Installer = Get-BootstrapperFixture -Name 'Lakes_SCREENView_4.0.1.exe' -Url 'https://www.weblakes.com/products/screen/update/Lakes_Environmental_SCREEN_View_V.4.0.1_Install.exe'
    $Result = Get-WinRarSfxInfo -Path $Installer

    $Result.Format | Should -Be 'WinRAR GUI SFX (RAR4)'
    $Result.ExecutedPayloads | Should -Contain 'setup.exe'
    $Result.Commands[0].Command.ArgumentList | Should -Contain '/w'
    $Result.NestedFiles | Should -Contain 'Lakes Environmental SCREEN View V.4.0.1.MSI'
  }
}
