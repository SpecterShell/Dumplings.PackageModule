# SPDX-License-Identifier: MIT

BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
}

Describe 'Durable test fixture cache' {
  BeforeEach {
    $Script:PreviousFixtureRoot = $env:DUMPLINGS_TEST_FIXTURE_ROOT
    $env:DUMPLINGS_TEST_FIXTURE_ROOT = Join-Path $TestDrive 'FixtureCache'
  }

  AfterEach {
    $env:DUMPLINGS_TEST_FIXTURE_ROOT = $Script:PreviousFixtureRoot
  }

  It 'adopts an existing nonempty fixture and writes integrity metadata' {
    $Directory = Get-DumplingsTestFixtureDirectory -Name 'Parser'
    $Path = Join-Path $Directory 'fixture.exe'
    [IO.File]::WriteAllBytes($Path, [byte[]](1, 2, 3, 4))

    Get-DumplingsTestFixture -Directory $Directory -Name 'fixture.exe' -Uri 'https://example.invalid/fixture.exe' | Should -Be $Path
    $Metadata = Get-Content -LiteralPath "$Path.fixture.json" -Raw | ConvertFrom-Json
    $Metadata.Length | Should -Be 4
    $Metadata.Sha256 | Should -Be (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
  }

  It 'rejects fixture directory traversal' {
    { Get-DumplingsTestFixtureDirectory -Name '..\escape' } | Should -Throw
  }

  It 'keeps identical helpers in both independently consumable submodules' {
    $OtherHelper = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\InstallerParsers\Tests\TestFixture.ps1'))
    (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'TestFixture.ps1') -Algorithm SHA256).Hash | Should -Be (Get-FileHash -LiteralPath $OtherHelper -Algorithm SHA256).Hash
  }
}
