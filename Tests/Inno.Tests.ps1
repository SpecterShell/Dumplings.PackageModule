BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallerBridge.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Inno.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\Inno'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [switch]$UseSourceForgeMetaRefresh
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url -UseSourceForgeMetaRefresh:$UseSourceForgeMetaRefresh
  }
}

Describe 'Inno bridge' {
  It 'Should normalize escaped AppId and user Program Files metadata through the bridge' {
    $Fixture = Get-InstallerFixture -Name 'kiro-ide-1.0.138-stable-win32-x64.exe' -Url 'https://prod.download.desktop.kiro.dev/releases/stable/win32-x64/signed/1.0.138/kiro-ide-1.0.138-stable-win32-x64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
    $Info.AppId | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}'
    $Info.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\Kiro'
    $Info.Scope | Should -Be 'user'
    Read-ProductCodeFromInno -Path $Fixture | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
  }

  It 'Should detect a default-machine dual-scope Inno installer through the bridge' {
    $Fixture = Get-InstallerFixture -Name 'WinSCP-6.5.6-Setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-InnoInfo -Path $Fixture

    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline', 'dialog')
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
    Test-InnoDualScope -Path $Fixture | Should -BeTrue
    Read-SupportedScopesFromInno -Path $Fixture | Should -Be @('user', 'machine')
    Read-UnsupportedArchitecturesFromInno -Path $Fixture | Should -BeNullOrEmpty
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should detect a default-user dual-scope Inno installer through the bridge' {
    $Fixture = Get-InstallerFixture -Name 'loot_0.26.0-win64.exe' -Url 'https://github.com/loot/loot/releases/download/0.26.0/loot_0.26.0-win64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.PrivilegesRequired | Should -Be 'lowest'
    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Test-InnoDualScope -Path $Fixture | Should -BeTrue
    Test-InnoUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-InnoUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeFalse
    Read-UnsupportedArchitecturesFromInno -Path $Fixture | Should -Be @('x86')
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should not treat a legacy Inno installer without command-line privilege overrides as dual-scope' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.SupportedArchitectures | Should -Be @('x86', 'x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
    Test-InnoDualScope -Path $Fixture | Should -BeFalse
    Read-SupportedScopesFromInno -Path $Fixture | Should -Be @('machine')
    Read-UnsupportedArchitecturesFromInno -Path $Fixture | Should -BeNullOrEmpty
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should detect Argente Inno wrappers that do not write their own Apps & Features entry through the bridge' {
    $FixtureName = 'Argente.DataShredder.x64.exe'
    $FixtureUrl = 'https://argenteutilities.com/en/download/datashredderx64'
    $Fixture = Get-InstallerFixture -Name $FixtureName -Url $FixtureUrl

    try {
      $Info = Get-InnoInfo -Path $Fixture
    } catch {
      Remove-Item -Path $Fixture -Force -ErrorAction SilentlyContinue
      $Fixture = Get-InstallerFixture -Name $FixtureName -Url $FixtureUrl
      $Info = Get-InnoInfo -Path $Fixture
    }

    $Info.InstallerType | Should -Be 'Inno'
    $Info.DisplayName | Should -Be 'Argente'
    $Info.AppId | Should -Be 'Argente'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.CreateUninstallRegKey | Should -Be 'yes'
    $Info.Uninstallable | Should -Be 'no'
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeFalse
  }
}
