. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

Describe 'Durable test fixture cache' {
  BeforeAll {
    $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
    $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
    $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
    . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  }

  BeforeEach {
    $Script:PreviousFixtureRoot = $env:DUMPLINGS_TEST_FIXTURE_ROOT
    $env:DUMPLINGS_TEST_FIXTURE_ROOT = Join-Path $TestDrive 'FixtureCache'
  }

  AfterEach {
    $env:DUMPLINGS_TEST_FIXTURE_ROOT = $Script:PreviousFixtureRoot
  }

  It 'adopts an existing nonempty fixture and writes integrity metadata' {
    $RelativePath = 'Installers\Test\Vendor.Package\1.0\fixture.exe'
    $Path = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath -EnsureParent
    [IO.File]::WriteAllBytes($Path, [byte[]](1, 2, 3, 4))

    Get-DumplingsTestFixture -RelativePath $RelativePath -Uri 'https://example.invalid/fixture.exe' | Should -Be $Path
    $Metadata = Get-Content -LiteralPath "$Path.fixture.json" -Raw | ConvertFrom-Json
    $Metadata.Length | Should -Be 4
    $Metadata.Sha256 | Should -Be (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
  }

  It 'downloads to an atomic partial path and leaves no partial artifacts' {
    $RelativePath = 'Installers\Test\Vendor.Package\1.0\downloaded.exe'
    Mock Invoke-WebRequest {
      [IO.File]::WriteAllBytes($OutFile, [byte[]](5, 6, 7, 8))
    }

    $Path = Get-DumplingsTestFixture -RelativePath $RelativePath -Uri 'https://example.invalid/downloaded.exe'

    [IO.File]::ReadAllBytes($Path) | Should -Be ([byte[]](5, 6, 7, 8))
    Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($Path)) -Filter '*.partial*' | Should -BeNullOrEmpty
    Should -Invoke Invoke-WebRequest -Times 1 -Exactly
  }

  It 'rejects cache metadata whose recorded length or hash does not match the file' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\Test\Vendor.Package\1.0\invalid.exe' -EnsureParent
    [IO.File]::WriteAllBytes($Path, [byte[]](1, 2, 3, 4))
    @{ Length = 5; Sha256 = '00' } | ConvertTo-Json | Set-Content -LiteralPath "$Path.fixture.json" -Encoding utf8NoBOM

    Test-DumplingsTestFixtureCacheEntry -Path $Path | Should -BeFalse
  }

  It 'reuses a valid fixture without issuing another request' {
    $RelativePath = 'Installers\Test\Vendor.Package\1.0\reused.exe'
    $Path = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath -EnsureParent
    [IO.File]::WriteAllBytes($Path, [byte[]](9, 10, 11, 12))
    Mock Invoke-WebRequest { throw 'A valid cache entry must not be downloaded again.' }

    Get-DumplingsTestFixture -RelativePath $RelativePath -Uri 'https://example.invalid/reused.exe' | Should -Be $Path
    Get-DumplingsTestFixture -RelativePath $RelativePath -Uri 'https://example.invalid/reused.exe' | Should -Be $Path
    Should -Invoke Invoke-WebRequest -Times 0 -Exactly
  }

  It 'serializes concurrent adoption of the same cache entry' {
    $RelativePath = 'Installers\Test\Vendor.Package\1.0\concurrent.exe'
    $Path = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath -EnsureParent
    [IO.File]::WriteAllBytes($Path, [byte[]](13, 14, 15, 16))
    $Helper = Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1'
    $Jobs = 1..4 | ForEach-Object {
      Start-ThreadJob -ScriptBlock {
        param($HelperPath, $Root, $FixtureRelativePath)
        $env:DUMPLINGS_TEST_FIXTURE_ROOT = $Root
        . $HelperPath
        Get-DumplingsTestFixture -RelativePath $FixtureRelativePath -Uri 'https://example.invalid/concurrent.exe'
      } -ArgumentList $Helper, $env:DUMPLINGS_TEST_FIXTURE_ROOT, $RelativePath
    }
    try {
      $Results = $Jobs | Receive-Job -Wait -AutoRemoveJob
      $Results | Should -HaveCount 4
      $Results | Select-Object -Unique | Should -Be $Path
      Test-DumplingsTestFixtureCacheEntry -Path $Path | Should -BeTrue
    } finally {
      $Jobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }
  }

  It 'rejects fixture path traversal' {
    { Resolve-DumplingsTestFixturePath -RelativePath '..\escape\fixture.exe' } | Should -Throw
  }

  It 'keeps identical helpers in both independently consumable submodules' {
    foreach ($Name in 'TestFixture.ps1', 'TestBootstrap.ps1', 'FixtureCatalog.psd1') {
      $PackageModulePath = Join-Path $Script:DumplingsTestRoot "Support\$Name"
      $InstallerParsersPath = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot "InstallerParsers\Tests\Support\$Name"))
      (Get-FileHash -LiteralPath $PackageModulePath -Algorithm SHA256).Hash | Should -Be (Get-FileHash -LiteralPath $InstallerParsersPath -Algorithm SHA256).Hash
    }
  }
}
