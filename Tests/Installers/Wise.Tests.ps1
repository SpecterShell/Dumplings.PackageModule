. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  . (Join-Path $Script:DumplingsModuleRoot 'Index.ps1')

  $Script:FixtureDirectory = $TestDrive
  $ProgressPreference = 'SilentlyContinue'

  function Get-WiseFixture {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$Url
    )
    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url
  }
}

Describe 'Wise MSI wrapper parser' {
  It 'Should parse TI Connect through its validated embedded MSI' {
    $Installer = Get-WiseFixture -Name 'TI-Connect-4.0.0.218.exe' -Url 'https://education.ti.com/download/en/ed-tech/14D11109C9F44D55B9BBF65E5A62E7F1/A885DD53BEC14496971FE5A42F1014CF/TI-Connect-4.0.0.218.exe'
    $Info = Get-WiseInfo -Path $Installer

    $Info.InstallerType | Should -Be 'Wise MSI'
    $Info.DisplayVersion | Should -Be '4.0.0.218'
    $Info.Publisher | Should -Be 'Texas Instruments Inc.'
    $Info.ProductCode | Should -Be '{D06BA64C-4447-49B4-B99D-E85BEA9E1035}'
    $Info.UpgradeCode | Should -Be '{FCEEDA79-4099-4C10-B717-F72EF53CCDA9}'
    $Info.Scope | Should -Be 'machine'
    $Info.NestedInstallerBuilder | Should -Be 'Wise'
    $Info.InstallLocationProperty | Should -Be 'INSTALLDIR'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.FileExtensions | Should -Contain '8xp'
    Test-WiseInstaller -Path $Installer | Should -BeTrue
  }
}

Describe 'WinGet analyzer Wise routing' {
  It 'Should prefer the Wise parser over generic EXE heuristics' {
    $Installer = Get-WiseFixture -Name 'TI-Connect-4.0.0.218.exe' -Url 'https://education.ti.com/download/en/ed-tech/14D11109C9F44D55B9BBF65E5A62E7F1/A885DD53BEC14496971FE5A42F1014CF/TI-Connect-4.0.0.218.exe'
    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'Wise' -and $_.Success } | Select-Object -First 1

    $Result.Result.Family | Should -Be 'Wise'
    $Result.Result.ProductCode | Should -Be '{D06BA64C-4447-49B4-B99D-E85BEA9E1035}'
    $Result.Result.SuggestedManifestFields.InstallerSwitches.InstallLocation | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
  }
}
