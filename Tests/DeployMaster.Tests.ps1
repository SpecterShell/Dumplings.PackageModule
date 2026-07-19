BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Compression', 'Archive', 'PE', 'RegistryAssociations', 'DeployMaster')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\AdditionalGenericExeParsers'
  $Script:DeployMasterFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\DeployMaster\Generated'
  $Script:DeployMasterLegacyFixture = Join-Path (Split-Path -Parent $Script:DeployMasterFixtureDirectory) 'Setup Brinno Video Player.exe'
}

Describe 'DeployMaster static parser' {
  It 'Should map controlled scope values without PE heuristics' {
    InModuleScope DeployMaster {
      (Get-DeployMasterScopeInfo -Value 0).Scope | Should -Be 'user'
      (Get-DeployMasterScopeInfo -Value 1).Scope | Should -Be 'machine'
      (Get-DeployMasterScopeInfo -Value 2).SupportedScopes | Should -Be @('user', 'machine')
      (Get-DeployMasterScopeInfo -Value 2).SupportsDualScope | Should -BeTrue
    }
  }

  $ArchitectureFixtures = @(
    @{ Name = 'KnownSetup_FileExt_32AppFor32Win.exe'; Installer = 'x86'; Mode = 'x86ApplicationForX86WindowsOnly'; Application = @('x86'); OperatingSystem = @('x86') }
    @{ Name = 'KnownSetup_FileExt_32AppFor32+64Win.exe'; Installer = 'x86'; Mode = 'x86ApplicationForX86AndX64Windows'; Application = @('x86'); OperatingSystem = @('x86', 'x64') }
    @{ Name = 'KnownSetup_FileExt_32+64AppFor32+64Win.exe'; Installer = 'x86'; Mode = 'x86AndX64Application'; Application = @('x86', 'x64'); OperatingSystem = @('x86', 'x64') }
    @{ Name = 'KnownSetup_FileExt_64AppFor64WinWith32InstallerStub.exe'; Installer = 'x86'; Mode = 'x64ApplicationWithX86InstallerStub'; Application = @('x64'); OperatingSystem = @('x64') }
    @{ Name = 'KnownSetup_FileExt_64AppFor64WinWithPure64Installer.exe'; Installer = 'x64'; Mode = 'x64ApplicationWithX64Installer'; Application = @('x64'); OperatingSystem = @('x64') }
  )
  It 'Should distinguish all controlled DeployMaster architecture modes' -ForEach $ArchitectureFixtures {
    $FixturePath = Join-Path $Script:DeployMasterFixtureDirectory $Name
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster architecture fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.InstallerArchitecture | Should -Be $Installer
    $Info.ApplicationArchitectureMode | Should -Be $Mode
    $Info.ApplicationArchitectures | Should -Be $Application
    $Info.SupportedOperatingSystemArchitectures | Should -Be $OperatingSystem
  }

  It 'Should decode file extensions, actions, and both runtime cores' {
    $AssociationFixture = Join-Path $Script:DeployMasterFixtureDirectory 'KnownSetup_FileExt_32+64AppFor32+64Win.exe'
    if (-not (Test-Path -LiteralPath $AssociationFixture)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster association fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'deploymaster-expanded'
    $Info = Get-DeployMasterInfo -Path $AssociationFixture
    $Files = @(Expand-DeployMasterInstaller -Path $AssociationFixture -DestinationPath $DestinationPath)

    $Info.DisplayName | Should -Be 'DMDeployMasterKnown'
    $Info.DisplayVersion | Should -Be '12.34.56'
    $Info.FileExtensions | Should -Be @('ext1', 'ext2')
    $Info.FileAssociations.Actions.Name | Should -Be @('Ext1Action1', 'Ext2Action1', 'Ext2Action2')
    $Info.ExtractedFiles | Should -Be @('license.txt', 'payload.txt', 'UnDeploy32.exe', 'UnDeploy64.exe')
    (Get-PELayout -Path (Join-Path $DestinationPath 'Runtime\DeployMasterCore-x86.exe')).MachineName | Should -Be 'I386'
    (Get-PELayout -Path (Join-Path $DestinationPath 'Runtime\DeployMasterCore-x64.exe')).MachineName | Should -Be 'AMD64'
    (Get-DumplingsTestFixtureHash -Path (Join-Path $DestinationPath 'Payload\payload.txt')) | Should -Be '82E809CEAC82F7E214B2E76901A01794929136ADA5243169CA78D953EE91E64D'
    $Files.Count | Should -Be 8
  }

  It 'Should parse and expand the legacy Brinno package table' {
    if (-not (Test-Path -LiteralPath $Script:DeployMasterLegacyFixture)) { Set-ItResult -Skipped -Because 'The legacy DeployMaster fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'deploymaster-legacy'
    $Info = Get-DeployMasterInfo -Path $Script:DeployMasterLegacyFixture
    $Files = @(Expand-DeployMasterInstaller -Path $Script:DeployMasterLegacyFixture -DestinationPath $DestinationPath -Name 'bvplay.exe')

    $Info.DisplayName | Should -Be 'Brinno Video Player'
    $Info.DisplayVersion | Should -Be '1.139.00'
    $Info.ProductCode | Should -Be 'Brinno Video Player'
    $Info.Scope | Should -Be 'machine'
    $Info.ExtractedFiles.Count | Should -Be 11
    $Files.Count | Should -Be 1
    (Get-PELayout -Path $Files[0].FullName).MachineName | Should -Be 'I386'
  }
}
