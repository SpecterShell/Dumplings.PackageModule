#Requires -Version 7.4

BeforeAll {
  $Script:UtilityModule = Import-Module (Join-Path $PSScriptRoot '..' 'Utilities' 'PlaywrightRuntime.psm1') -Force -PassThru
  $Script:LockPath = Join-Path $PSScriptRoot '..' 'Assets' 'PlaywrightRuntime.psd1'
}

AfterAll {
  Remove-Module -ModuleInfo $Script:UtilityModule -Force -ErrorAction SilentlyContinue
}

Describe 'Pinned Patchright runtime cache' {
  It 'uses a versioned official package URI and a SHA-256 lock' {
    $Lock = Import-PowerShellDataFile -LiteralPath $Script:LockPath

    $Lock.RuntimeId | Should -BeExactly 'Patchright'
    $Lock.Version | Should -Match '^\d+\.\d+\.\d+$'
    $Lock.PackageUri | Should -BeLike 'https://api.nuget.org/v3-flatcontainer/patchright/*'
    $Lock.PackageSha256 | Should -Match '^[0-9A-F]{64}$'
  }

  It 'rejects an incomplete runtime without attempting network access' {
    $RuntimePath = Join-Path $TestDrive 'Incomplete'
    $null = New-Item -Path $RuntimePath -ItemType Directory

    Test-DumplingsPlaywrightRuntime -Path $RuntimePath -Version '1.0.0' | Should -BeFalse
  }

  It 'validates the assembly, driver, and retained license layout' {
    $RuntimePath = Join-Path $TestDrive 'Complete'
    $NodeDirectory = Join-Path $RuntimePath '.playwright' 'node'
    $DriverDirectory = Join-Path $RuntimePath '.playwright' 'package'
    $null = New-Item -Path (Join-Path $NodeDirectory 'win32_x64') -ItemType Directory -Force
    $null = New-Item -Path $DriverDirectory -ItemType Directory -Force
    $AssemblyPath = [Management.Automation.PSObject].Assembly.Location
    Copy-Item -LiteralPath $AssemblyPath -Destination (Join-Path $RuntimePath 'Microsoft.Playwright.dll')
    Set-Content -LiteralPath (Join-Path $NodeDirectory 'win32_x64' 'node.exe') -Value 'fixture'
    Set-Content -LiteralPath (Join-Path $NodeDirectory 'LICENSE') -Value 'fixture'
    Set-Content -LiteralPath (Join-Path $DriverDirectory 'cli.js') -Value 'fixture'
    Set-Content -LiteralPath (Join-Path $DriverDirectory 'LICENSE') -Value 'fixture'
    $AssemblyVersion = [Reflection.AssemblyName]::GetAssemblyName($AssemblyPath).Version
    $ExpectedVersion = '{0}.{1}.{2}' -f $AssemblyVersion.Major, $AssemblyVersion.Minor, $AssemblyVersion.Build

    Test-DumplingsPlaywrightRuntime -Path $RuntimePath -Version $ExpectedVersion | Should -BeTrue
  }
}
