BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Compression', 'Archive', 'PE', 'RegistryAssociations', 'InstallMate')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\AdditionalGenericExeParsers'
  $Script:InstallMateFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallMate\Generated'
  $Script:InstallMateLegacyFixture = Join-Path (Split-Path -Parent $Script:InstallMateFixtureDirectory) 'PoP8Setup.exe'
}

Describe 'InstallMate static parser' {
  It 'Should map documented PE execution levels to InstallMate scope behavior' {
    InModuleScope InstallMate {
      $Required = Get-InstallMateScopeInfo -RequestedExecutionLevel requireAdministrator
      $Highest = Get-InstallMateScopeInfo -RequestedExecutionLevel highestAvailable
      $Invoker = Get-InstallMateScopeInfo -RequestedExecutionLevel asInvoker

      $Required.Scope | Should -Be 'machine'
      $Required.SupportedScopes | Should -Be @('machine')
      $Highest.SupportedScopes | Should -Be @('user', 'machine')
      $Highest.SupportsDualScope | Should -BeTrue
      $Invoker.Scope | Should -Be 'user'
      $Invoker.DefaultScope | Should -Be 'user'
      $Invoker.SupportedScopes | Should -Be @('user')
      $Invoker.SupportsDualScope | Should -BeFalse
    }
  }

  $InstallLevelFixtures = @(
    @{ Level = 0; LevelName = 'NotChecked'; Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); Dual = $false }
    @{ Level = 1; LevelName = 'CurrentUser'; Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); Dual = $false }
    @{ Level = 2; LevelName = 'AllUsersOrCurrentUser'; Scope = $null; DefaultScope = 'machine'; SupportedScopes = @('user', 'machine'); Dual = $true }
    @{ Level = 3; LevelName = 'AllUsersQueryCurrentUser'; Scope = $null; DefaultScope = 'machine'; SupportedScopes = @('user', 'machine'); Dual = $true }
    @{ Level = 4; LevelName = 'AllUsers'; Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); Dual = $false }
    @{ Level = 5; LevelName = 'Administrator'; Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); Dual = $false }
  )
  It 'Should decode controlled InstallMate install level <Level>' -ForEach $InstallLevelFixtures {
    $FixturePath = Join-Path $Script:InstallMateFixtureDirectory "InstallMateKnown-Level$Level.exe"
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate scope fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Info.ArchiveInfo.FormatVersion | Should -Be '15.11'
    $Info.DatabaseInfo.Signature | Should -Be 'tinB'
    $Info.InstallLevel | Should -Be $Level
    $Info.InstallLevelName | Should -Be $LevelName
    $Info.Scope | Should -Be $Scope
    $Info.DefaultScope | Should -Be $DefaultScope
    $Info.SupportedScopes | Should -Be $SupportedScopes
    $Info.SupportsDualScope | Should -Be $Dual
    $Info.CanExpand | Should -BeTrue
  }

  It 'Should read controlled PE identity and named InstallMate codes' {
    $FixturePath = Join-Path $Script:InstallMateFixtureDirectory 'InstallMateKnown-Level4.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate identity fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Info.DisplayName | Should -Be 'Dumplings InstallMate Fixture'
    $Info.DisplayVersion | Should -Be '12.34.56.78'
    $Info.Publisher | Should -Be 'Dumplings Parser Tests'
    $Info.ProductCode | Should -Be '{6D6D51D2-ACB3-49A5-B546-E6EC581DF39D}'
    $Info.ProductCodeEvidence | Should -BeLike '*StringFileInfo.ProductCode*'
  }

  It 'Should decode and selectively expand a legacy InstallMate package' {
    if (-not (Test-Path -LiteralPath $Script:InstallMateLegacyFixture)) { Set-ItResult -Skipped -Because 'The legacy InstallMate fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'installmate-legacy'
    $Info = Get-InstallMateInfo -Path $Script:InstallMateLegacyFixture
    $Files = @(Expand-InstallMateInstaller -Path $Script:InstallMateLegacyFixture -DestinationPath $DestinationPath -Name 'WebView2Loader.dll')

    $Info.DisplayName | Should -Be "Harzing's Publish or Perish"
    $Info.DisplayVersion | Should -Be '8.19.5300.9483'
    $Info.DatabaseInfo.Signature | Should -Be 'tin9'
    $Info.DatabaseInfo.FileRecordCount | Should -Be 7
    $Info.CanExpand | Should -BeTrue
    $Files.Count | Should -Be 2
    @($Files | ForEach-Object { $_.Length } | Sort-Object) | Should -Be @(116200, 165336)
    @($Files | ForEach-Object { Get-DumplingsTestFixtureHash -Path $_.FullName } | Sort-Object) | Should -Be @(
      '465A7DDFB3A0DA4C3965DAF2AD6AC7548513F42329B58AEBC337311C10EA0A6F'
      'CC2F661AAC9C05646933F717E629A69BE93D8D06803066289D6DC1105AAC6CD2'
    )
  }

  It 'Should validate a bounded tiz3 header and fail closed on malformed compressed data' {
    $Bytes = [byte[]]::new(2048)
    [Text.Encoding]::ASCII.GetBytes('tiz3').CopyTo($Bytes, 1024)
    [BitConverter]::GetBytes([uint16]12).CopyTo($Bytes, 1028)
    [BitConverter]::GetBytes([uint16]11).CopyTo($Bytes, 1030)
    [BitConverter]::GetBytes([uint64]1024).CopyTo($Bytes, 1040)
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-installmate.exe'
    [IO.File]::WriteAllBytes($FixturePath, $Bytes)

    InModuleScope InstallMate -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 0; Size = 0 } } } }
      Mock Get-PEOverlayOffset { 1024 }
      Mock Get-PERequestedExecutionLevel { 'highestAvailable' }
      Mock Get-PEVersionStringTable { [pscustomobject]@{ ProductCode = '{11111111-2222-3333-4444-555555555555}'; PackageCode = '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}' } }
      $Info = Get-InstallMateInfo -Path $FixturePath

      $Info.ArchiveInfo.Signature | Should -Be 'tiz3'
      $Info.ArchiveInfo.FormatVersion | Should -Be '12.11'
      $Info.ProductCode | Should -Be '{11111111-2222-3333-4444-555555555555}'
      $Info.ProductCodeEvidence | Should -BeLike '*StringFileInfo.ProductCode*'
      $Info.PackageCode | Should -Be '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
      $Info.Scope | Should -BeNullOrEmpty
      $Info.SupportedScopes | Should -Be @('user', 'machine')
      $Info.SupportsDualScope | Should -BeTrue
      $Info.ScopeConfidence | Should -Be 'conditional'
      $Info.CanExpand | Should -BeFalse
      @($Info.Warnings | Where-Object { $_ -like '*setup database could not be decoded*' }).Count | Should -Be 1
      { Expand-InstallMateInstaller -Path $FixturePath } | Should -Throw
    }
  }
}
