BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Burn.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\Burn'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }
}

Describe 'Burn unsupported architecture parser' {
  It 'Should detect the x64-only Enpass Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'Enpass-setup.exe' -Url 'https://dl.enpass.io/stable/windows/setup/x64/6.12.1.2417/Enpass-setup.exe'
    $Info = Get-BurnPackageArchitectureInfo -Path $Fixture

    $Info.BundleArchitecture | Should -Be 'x86'
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Read-UnsupportedArchitecturesFromBurn -Path $Fixture | Should -Be @('x86')
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeFalse
  }

  It 'Should detect the x64-only Jabra Direct Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'JabraDirectSetup.exe' -Url 'https://jabraxpressonlineprdstor.blob.core.windows.net/jdo/JabraDirectSetup.exe'
    $Info = Get-BurnPackageArchitectureInfo -Path $Fixture

    $Info.BundleArchitecture | Should -Be 'x86'
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Read-UnsupportedArchitecturesFromBurn -Path $Fixture | Should -Be @('x86')
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeFalse
  }
}

Describe 'Burn scope parser' {
  It 'Should detect a default-machine Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'Enpass-setup.exe' -Url 'https://dl.enpass.io/stable/windows/setup/x64/6.12.1.2417/Enpass-setup.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.SupportsDualScope | Should -BeFalse
    Read-ScopeFromBurn -Path $Fixture | Should -Be 'machine'
    Read-SupportedScopesFromBurn -Path $Fixture | Should -Be @('machine')
    Test-BurnDualScope -Path $Fixture | Should -BeFalse
  }

  It 'Should detect a default-user Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'Proton Drive Setup 3.0.2.exe' -Url 'https://proton.me/download/drive/windows/3.0.2/x64/Proton%20Drive%20Setup%203.0.2.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    Read-ScopeFromBurn -Path $Fixture | Should -Be 'user'
    Read-SupportedScopesFromBurn -Path $Fixture | Should -Be @('user')
    Test-BurnDualScope -Path $Fixture | Should -BeFalse
  }

  It 'Should not treat hidden all-users Grammarly packages as command-line dual-scope' {
    $Fixture = Get-InstallerFixture -Name 'GrammarlyAddInSetup6.8.263.exe' -Url 'https://download-office.grammarly.com/installer/GrammarlyAddInSetup6.8.263.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.PackageScopes | Should -Contain 'machine'
    $Info.PackageScopes | Should -Contain 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    Test-BurnDualScope -Path $Fixture | Should -BeFalse
  }

  It 'Should detect Python 3.13 as dual-scope through InstallAllUsers' {
    $Fixture = Get-InstallerFixture -Name 'python-3.13.9-amd64.exe' -Url 'https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.OverridableScopeVariables | Should -Contain 'InstallAllUsers'
    Test-BurnDualScope -Path $Fixture | Should -BeTrue
  }

  It 'Should detect Python 3.14 as dual-scope through InstallAllUsers' {
    $Fixture = Get-InstallerFixture -Name 'python-3.14.6-amd64.exe' -Url 'https://www.python.org/ftp/python/3.14.6/python-3.14.6-amd64.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.OverridableScopeVariables | Should -Contain 'InstallAllUsers'
    Read-SupportedScopesFromBurn -Path $Fixture | Should -Be @('user', 'machine')
    Test-BurnDualScope -Path $Fixture | Should -BeTrue
  }
}
