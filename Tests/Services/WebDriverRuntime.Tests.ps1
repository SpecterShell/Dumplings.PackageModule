# SPDX-License-Identifier: Apache-2.0
. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  . (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
  Import-Module (Resolve-DumplingsTestModulePath 'Utilities\WebDriverRuntime.psm1') -Force
}

Describe 'Edge driver build selection' -Tag Unit {
  BeforeEach {
    Mock Get-Command { [pscustomobject]@{ Source = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe' } } -ModuleName WebDriverRuntime
    Mock Get-Item { [pscustomobject]@{ VersionInfo = [pscustomobject]@{ ProductVersion = '157.0.4341.60' } } } -ModuleName WebDriverRuntime
    Mock Test-Path { $true } -ModuleName WebDriverRuntime
  }

  It 'uses the published build when it shares the browser major version' {
    $Cache = Join-Path $TestDrive 'driver'
    Mock Invoke-WebRequest { [pscustomobject]@{ Content = "157.0.4341.57`r`n" } } -ModuleName WebDriverRuntime
    $Result = Install-DumplingsWebDriver -Browser Edge -CacheRoot $Cache
    $Result.Version | Should -Be ([version]'157.0.4341.57')
    $Result.Directory | Should -BeExactly (Join-Path $Cache 'Edge-157.0.4341.57')
  }

  It 'warns when the published build has a different build number' {
    Mock Invoke-WebRequest { [pscustomobject]@{ Content = "157.0.4340.20`r`n" } } -ModuleName WebDriverRuntime
    $Result = Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver') -WarningVariable Warnings -WarningAction SilentlyContinue
    $BrowserTriplet = Get-DumplingsVersionTriplet -Version ([version]'157.0.4341.60')
    $Result.Version | Should -Be ([version]'157.0.4340.20')
    $Warnings | Should -Match ([regex]::Escape("Edge $BrowserTriplet has no published driver"))
  }

  It 'refuses a published build from another major version' {
    Mock Invoke-WebRequest { [pscustomobject]@{ Content = "158.0.4370.33`r`n" } } -ModuleName WebDriverRuntime
    { Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver') } | Should -Throw '*No Microsoft.EdgeDriver build exists*'
  }

  It 'refuses to install when the release document does not name a version' {
    Mock Invoke-WebRequest { [pscustomobject]@{ Content = '' } } -ModuleName WebDriverRuntime
    { Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver') } | Should -Throw '*No Microsoft.EdgeDriver build exists*'
  }
}

Describe 'Edge driver package naming' -Tag Unit {
  It 'downloads the package that matches the operating-system architecture' {
    Mock Get-Command { [pscustomobject]@{ Source = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe' } } -ModuleName WebDriverRuntime
    Mock Get-Item { [pscustomobject]@{ VersionInfo = [pscustomobject]@{ ProductVersion = '157.0.4341.60' } } } -ModuleName WebDriverRuntime
    Mock Invoke-WebRequest { [pscustomobject]@{ Content = "157.0.4341.57`r`n" } } -ModuleName WebDriverRuntime -ParameterFilter { $Uri -like '*LATEST_RELEASE*' }
    Mock Invoke-WebRequest { } -ModuleName WebDriverRuntime -ParameterFilter { $Uri -like '*edgedriver_*.zip' }
    Mock Test-Path { $false } -ModuleName WebDriverRuntime
    Mock Expand-Archive { } -ModuleName WebDriverRuntime
    $Expected = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
      'Arm64' { 'arm64' }
      'X86' { 'win32' }
      default { 'win64' }
    }

    { Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver') } | Should -Throw '*did not contain*'

    Should -Invoke Invoke-WebRequest -ModuleName WebDriverRuntime -ParameterFilter { $Uri -like "*edgedriver_$Expected.zip" }
  }
}

Describe 'Installed browser discovery' -Tag Unit {
  It 'reads the release document for the installed browser major version' {
    Mock Invoke-WebRequest { throw 'The specified blob does not exist.' } -ModuleName WebDriverRuntime
    { Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver') } | Should -Throw '*No Microsoft.EdgeDriver build exists*'
    Should -Invoke Invoke-WebRequest -ModuleName WebDriverRuntime -ParameterFilter { $Uri -match 'LATEST_RELEASE_\d+$' }
  }

  It 'throws when the browser is absent' {
    Mock Get-Command { $null } -ModuleName WebDriverRuntime
    Mock Get-ItemProperty { $null } -ModuleName WebDriverRuntime
    Mock Test-Path { $false } -ModuleName WebDriverRuntime
    { Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver') } | Should -Throw '*is not installed*'
  }
}

Describe 'Version triplet' -Tag Unit {
  It 'ignores the fourth component and separates the third' {
    Get-DumplingsVersionTriplet -Version ([version]'157.0.4341.60') | Should -BeExactly (Get-DumplingsVersionTriplet -Version ([version]'157.0.4341.99'))
    Get-DumplingsVersionTriplet -Version ([version]'157.0.4341.60') | Should -Not -BeExactly (Get-DumplingsVersionTriplet -Version ([version]'157.0.4340.60'))
  }
}

Describe 'Edge driver release document' -Tag Unit {
  BeforeEach {
    Mock Get-Command { [pscustomobject]@{ Source = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe' } } -ModuleName WebDriverRuntime
    Mock Get-Item { [pscustomobject]@{ VersionInfo = [pscustomobject]@{ ProductVersion = '157.0.4341.60' } } } -ModuleName WebDriverRuntime
    Mock Test-Path { $true } -ModuleName WebDriverRuntime
  }

  It 'decodes the vendor UTF-16 release document' {
    Mock Invoke-WebRequest { [pscustomobject]@{ Content = [byte[]]@((0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes("157.0.4341.60`r`n")) } } -ModuleName WebDriverRuntime
    $Result = Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver')
    $Result.Version | Should -Be ([version]'157.0.4341.60')
  }

  It 'decodes a plain text release document' {
    Mock Invoke-WebRequest { [pscustomobject]@{ Content = "157.0.4341.42`r`n" } } -ModuleName WebDriverRuntime
    $Result = Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver')
    $Result.Version | Should -Be ([version]'157.0.4341.42')
  }

  It 'refuses to install when the vendor has no build for the major version' {
    Mock Invoke-WebRequest { throw 'The specified blob does not exist.' } -ModuleName WebDriverRuntime
    { Install-DumplingsWebDriver -Browser Edge -CacheRoot (Join-Path $TestDrive 'driver') } | Should -Throw '*No Microsoft.EdgeDriver build exists*'
  }
}
