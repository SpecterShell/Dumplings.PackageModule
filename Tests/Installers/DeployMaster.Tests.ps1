. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive
  $Script:DeployMasterFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\DeployMaster\Current\KnownScenarios'
  $Script:DeployMasterOptionFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\DeployMaster\Current\OptionMatrix'
  $Script:DeployMasterBehaviorFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\DeployMaster\Current\BehaviorMatrix'
  $Script:DeployMasterValidationFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\DeployMaster\Current\ValidationScenarios'
  $Script:DeployMasterLegacyFixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Setup Brinno Video Player.exe')
  $Script:DeployMasterHistoricalFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\DeployMaster\JGsoft.DeployMaster'
  $Script:DeployMasterClassicFixture = Join-Path $Script:DeployMasterHistoricalFixtureDirectory '2.5.3\SetupDeployMasterDemo.exe'
}

Describe 'DeployMaster static parser' {
  It 'Should normalize private DeployMaster data-root variables without losing raw path evidence' {
    InModuleScope DeployMaster {
      ConvertTo-DeployMasterEnvironmentPath -Value '%LOCALAPPDATAROOT%\Vendor\App' | Should -Be '%LOCALAPPDATA%\Vendor\App'
      ConvertTo-DeployMasterEnvironmentPath -Value '%APPDATAROOT%\Vendor\App' | Should -Be '%APPDATA%\Vendor\App'
      ConvertTo-DeployMasterEnvironmentPath -Value '%COMMONAPPDATAROOT%\Vendor\App' | Should -Be '%ProgramData%\Vendor\App'
      ConvertTo-DeployMasterEnvironmentPath -Value '%APPFOLDER%\Data' | Should -Be '%APPFOLDER%\Data'
    }
  }

  It 'Should decode behavioral metadata when the project has no auxiliary payloads' {
    $FixturePath = Join-Path $Script:DeployMasterValidationFixtureDirectory 'LicenseFreeMixed.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The license-free DeployMaster validation fixture is not cached.'; return }

    $Info = Get-DeployMasterInfo -Path $FixturePath
    $Info.PackageSettings.PortableInstallationMode | Should -Be 'UserChoice'
    $Info.Components.Count | Should -Be 1
    $Info.InstalledFiles.Count | Should -Be 1
    $Info.BuiltInRegistrationVariants.Count | Should -Be 4
    $Info.UnresolvedFields | Should -BeNullOrEmpty
    @($Info.Diagnostics | Where-Object Id -EQ 'DeployMaster.Metadata.BehavioralStreamIncomplete') | Should -BeNullOrEmpty
  }

  It 'Should parse and expand the classic BZip2 package route' {
    if (-not (Test-Path -LiteralPath $Script:DeployMasterClassicFixture)) { Set-ItResult -Skipped -Because 'The classic DeployMaster fixture is not cached.'; return }

    Test-DeployMaster -Path $Script:DeployMasterClassicFixture | Should -BeTrue
    $Info = Get-DeployMasterInfo -Path $Script:DeployMasterClassicFixture
    $ExtractionPath = Join-Path $TestDrive 'DeployMasterClassic'
    $Files = @(Expand-DeployMasterInstaller -Path $Script:DeployMasterClassicFixture -DestinationPath $ExtractionPath -Name 'Payload/identity.c' -CollisionAction Rename)
    $AuxiliaryFiles = @(Expand-DeployMasterInstaller -Path $Script:DeployMasterClassicFixture -DestinationPath $ExtractionPath -Name 'Payload/DeployMaster32.ico' -CollisionAction Rename)

    $Info.DisplayName | Should -Be 'DeployMaster Demo'
    $Info.DisplayVersion | Should -Be '2.5.3'
    $Info.Publisher | Should -Be 'JGsoft'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%PROGRAMFILES%\JGsoft\DeployMaster Demo'
    $Info.ProductCode | Should -Be 'DeployMaster Demo'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries.Count | Should -Be 1
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'DeployMaster Demo'
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'JGsoft DeployMaster Demo 2.5.3'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'DisplayVersion'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'Publisher'
    $Info.UninstallString | Should -Be '%WINDOWS%\UnDeploy.exe "%PROGRAMFILES%\JGsoft\DeployMaster Demo\Deploy.log"'
    $Info.BuiltInRegistration.Root | Should -Be 'HKLM'
    $Info.BuiltInRegistration.RegistryView | Should -Be '32-bit'
    $Info.BuiltInRegistration.RuntimeGeneratedValueNames | Should -Be @('Stub')
    @($Info.RegistryWrites | Where-Object { $_.Key -eq 'Software\JGsoft\DeployIT' -and $_.Name -eq 'DeployMaster Demo' }).Count | Should -Be 1
    $Info.FileEntries.Count | Should -Be 16
    $Info.FileEntries[0].FullName | Should -Be 'DeployMaster32.ico'
    $Info.FileEntries[0].IsAuxiliary | Should -BeTrue
    $Info.FileEntries[4].FullName | Should -Be 'identity.c'
    $Info.FileEntries[-1].FullName | Should -Be 'UnDeploy.exe'
    $Info.ClassicFileCatalog.EntryCount | Should -Be 16
    $Info.ClassicFileCatalog.AuxiliaryEntryCount | Should -Be 4
    $Info.ClassicFileCatalog.DestinationRoot.FullName | Should -Be '%APPFOLDER%'
    $Info.Components.Name | Should -Be @('DeployMaster', 'Documentation', 'Language Files', 'Sample Support DLLs', 'Shortcut Icons')
    $Info.Components[0].InstalledByDefault | Should -BeTrue
    $Info.Components[0].UserSelectable | Should -BeFalse
    $Info.Components[1].Requirements | Should -Be @(0)
    $Info.InstallationFolders.FullName | Should -Be @('%APPFOLDER%', '%APPMENU%', '%APPFOLDER%\Samples', '%APPMENU%\Self-Running Demonstrations', '%DESKTOP%')
    $Info.InstallationItemGroups.Count | Should -Be 8
    $Info.InstalledFiles.Count | Should -Be 12
    $Info.InstalledFiles.FileIndex | Should -Contain 2
    $Info.InstalledFiles.FileIndex | Should -Contain 14
    ($Info.InstalledFiles | Where-Object GroupIndex -EQ 0 | Select-Object -ExpandProperty Directory -Unique) | Should -Be '%APPFOLDER%'
    ($Info.InstalledFiles | Where-Object GroupIndex -EQ 0 | Select-Object -ExpandProperty DestinationPath) | Should -Contain '%APPFOLDER%\DeployMaster.exe'
    ($Info.InstalledFiles | Where-Object GroupIndex -EQ 2 | Select-Object -ExpandProperty Directory -Unique) | Should -Be '%APPFOLDER%'
    ($Info.InstalledFiles | Where-Object GroupIndex -EQ 4 | Select-Object -ExpandProperty DestinationPath) | Should -Contain '%APPFOLDER%\Samples\identity.c'
    $Info.InstallationItemGroups.ComponentIndex | Should -Be @(0, 0, 1, 2, 3, 4, 4, 4)
    $Info.Shortcuts.Count | Should -Be 4
    $Info.Shortcuts.TargetFile | Should -Contain 'DeployMaster.exe'
    $Info.UrlShortcuts.Count | Should -Be 6
    $Info.UrlShortcuts.Name | Should -Contain 'DeployMaster web site'
    $Info.FileExtensions | Should -Be @('deploy')
    $Info.FileAssociations.Count | Should -Be 1
    $Info.FileAssociations[0].Description | Should -Be 'DeployMaster Setup Script'
    $Info.FileAssociations[0].CreateByDefault | Should -BeNullOrEmpty
    $Info.FileAssociations[0].Actions.Name | Should -Be @('Open', 'Build')
    $Info.FileAssociations[0].Actions.Executable32FileIndex | Should -Be @(13, 13)
    $Info.FileAssociations[0].Actions.Executable64FileIndex | Should -Be @(-1, -1)
    $Info.CustomRegistryWrites.Count | Should -Be 1
    $Info.CustomRegistryWrites[0].Root | Should -Be 'HKCU'
    $Info.CustomRegistryWrites[0].Key | Should -Be 'Software\JGsoft\DeployMaster'
    $Info.CustomRegistryWrites[0].Name | Should -Be 'License'
    $Info.CustomRegistryWrites[0].Type | Should -Be 'REG_DWORD'
    $Info.CustomRegistryWrites[0].Value | Should -Be 1
    $Info.UnresolvedFields | Should -Not -Contain 'RegistryWrites'
    $Info.UnresolvedFields | Should -Not -Contain 'FileAssociations'
    $Info.UnresolvedFields | Should -Not -Contain 'InstallationItems'
    $Info.UnresolvedFields | Should -Not -Contain 'InstallationItemDestinations'
    $Info.UnresolvedFields | Should -Not -Contain 'InstallerSwitches'
    $Info.ParserVersionInfo.FormatProfile | Should -Be 'ClassicBZip2'
    @($Info.Diagnostics | Where-Object Id -EQ 'DeployMaster.Metadata.ClassicArpUnresolved') | Should -BeNullOrEmpty
    @($Info.Diagnostics | Where-Object Id -EQ 'DeployMaster.Installability.ClassicInteractiveOnly').Count | Should -Be 1
    @($Info.Diagnostics | Where-Object Id -EQ 'DeployMaster.Installability.SupportDllEffectsOpaque').Count | Should -Be 1
    $Info.SupportDlls | Should -HaveCount 1
    $Info.SupportDlls[0].Architecture | Should -Be 'x86'
    $Info.SupportDlls[0].FileName | Should -Be 'InstallDemo.dll'
    $Info.UnresolvedFields | Should -Contain 'SupportDllEffects'
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 3555
    (Get-DumplingsTestFixtureHash -Path $Files[0].FullName) | Should -Be 'F699A4CD7A5FCB943A9FF576468C4C41374E582326F6813D008ECAF8A5E378E1'
    $AuxiliaryFiles.Count | Should -Be 1
    $AuxiliaryFiles[0].Length | Should -Be 3262
    (Get-DumplingsTestFixtureHash -Path $AuxiliaryFiles[0].FullName) | Should -Be 'A5DFC9F5D6F26BEA4019500913A6B435481CD1AA81FB0DE2E30C4CEA8D4DFC91'
  }

  It 'Should reject a truncated classic payload chain deterministically' {
    if (-not (Test-Path -LiteralPath $Script:DeployMasterClassicFixture)) { Set-ItResult -Skipped -Because 'The classic DeployMaster fixture is not cached.'; return }
    $TruncatedPath = Join-Path $TestDrive 'DeployMasterClassic-Truncated.exe'
    Copy-Item -LiteralPath $Script:DeployMasterClassicFixture -Destination $TruncatedPath
    $Stream = [IO.File]::Open($TruncatedPath, 'Open', 'ReadWrite', 'None')
    try { $Stream.SetLength($Stream.Length - 1) } finally { $Stream.Dispose() }

    Test-DeployMaster -Path $TruncatedPath | Should -BeFalse
    { Get-DeployMasterInfo -Path $TruncatedPath } | Should -Throw '*payload records do not have a matching filename catalog*'
  }

  It 'Should remove a partial classic payload when its expansion exceeds the output limit' {
    if (-not (Test-Path -LiteralPath $Script:DeployMasterClassicFixture)) { Set-ItResult -Skipped -Because 'The classic DeployMaster fixture is not cached.'; return }
    $OutputDirectory = Join-Path $TestDrive 'DeployMasterClassic-Bounded'
    $OutputPath = Join-Path $OutputDirectory 'Payload\identity.c'

    { Expand-DeployMasterInstaller -Path $Script:DeployMasterClassicFixture -DestinationPath $OutputDirectory -Name 'Payload/identity.c' -MaximumExpandedBytes 1 -CollisionAction Error } | Should -Throw '*1-byte*limit*'
    Test-Path -LiteralPath $OutputPath | Should -BeFalse
  }

  It 'Should map controlled scope values without PE heuristics' {
    InModuleScope DeployMaster {
      (Get-DeployMasterScopeInfo -Value 0).Scope | Should -Be 'user'
      (Get-DeployMasterScopeInfo -Value 1).Scope | Should -Be 'machine'
      (Get-DeployMasterScopeInfo -Value 2).SupportedScopes | Should -Be @('user', 'machine')
      (Get-DeployMasterScopeInfo -Value 2).SupportsDualScope | Should -BeTrue
    }
  }

  $ArchitectureFixtures = @(
    @{ Name = 'KnownSetup_FileExt_32AppFor32Win.exe'; Installer = 'x86'; Mode = 'x86ApplicationForX86WindowsOnly'; Application = @('x86'); OperatingSystem = @('x86'); RegistryView = '32-bit' }
    @{ Name = 'KnownSetup_FileExt_32AppFor32+64Win.exe'; Installer = 'x86'; Mode = 'x86ApplicationForX86AndX64Windows'; Application = @('x86'); OperatingSystem = @('x86', 'x64'); RegistryView = '32-bit' }
    @{ Name = 'KnownSetup_FileExt_32+64AppFor32+64Win.exe'; Installer = 'x86'; Mode = 'x86AndX64Application'; Application = @('x86', 'x64'); OperatingSystem = @('x86', 'x64'); RegistryView = 'architecture-selected' }
    @{ Name = 'KnownSetup_FileExt_64AppFor64WinWith32InstallerStub.exe'; Installer = 'x86'; Mode = 'x64ApplicationWithX86InstallerStub'; Application = @('x64'); OperatingSystem = @('x64'); RegistryView = '64-bit' }
    @{ Name = 'KnownSetup_FileExt_64AppFor64WinWithPure64Installer.exe'; Installer = 'x64'; Mode = 'x64ApplicationWithX64Installer'; Application = @('x64'); OperatingSystem = @('x64'); RegistryView = '64-bit' }
  )
  It 'Should distinguish all controlled DeployMaster architecture modes' -ForEach $ArchitectureFixtures {
    $FixturePath = Join-Path $Script:DeployMasterFixtureDirectory $Name
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster architecture fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.InstallerArchitecture | Should -Be $Installer
    $Info.ApplicationArchitectureMode | Should -Be $Mode
    $Info.ApplicationArchitectures | Should -Be $Application
    $Info.SupportedOperatingSystemArchitectures | Should -Be $OperatingSystem
    $Info.RegistryView | Should -Be $RegistryView
  }

  It 'Should decode file extensions, actions, and both runtime cores' {
    $AssociationFixture = Join-Path $Script:DeployMasterFixtureDirectory 'KnownSetup_FileExt_32+64AppFor32+64Win.exe'
    if (-not (Test-Path -LiteralPath $AssociationFixture)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster association fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'deploymaster-expanded'
    $Info = Get-DeployMasterInfo -Path $AssociationFixture
    $Files = @(Expand-DeployMasterInstaller -Path $AssociationFixture -DestinationPath $DestinationPath -CollisionAction Rename)

    $Info.DisplayName | Should -Be 'DMDeployMasterKnown'
    $Info.DisplayVersion | Should -Be '12.34.56'
    $Info.Publisher | Should -Be 'Dumplings Parser Lab'
    $Info.LicenseFileName | Should -Be 'license.txt'
    $Info.LicenseRequiredEveryInstall | Should -BeTrue
    $Info.FileExtensions | Should -Be @('ext1', 'ext2')
    $Info.FileAssociations.Actions.Name | Should -Be @('Ext1Action1', 'Ext2Action1', 'Ext2Action2')
    $Info.Components.Count | Should -Be 1
    $Info.Components[0].InstallByDefault | Should -BeTrue
    $Info.Components[0].UserSelectable | Should -BeTrue
    $Info.InstalledFiles.DestinationPath | Should -Be '%APPFOLDER%\payload.txt'
    $Info.CompletionActions.ShowMessage | Should -BeTrue
    $Info.CompletionActions.ShowStartMenuFolder | Should -BeTrue
    $Info.CompletionActions.PromptForReboot | Should -BeFalse
    $Info.UpdatePolicy.DeleteObsoleteFiles | Should -BeFalse
    $Info.UpdatePolicy.RequiredReleaseDate | Should -BeNullOrEmpty
    $Info.PackageSettings.PortableInstallationMode | Should -Be 'UserChoice'
    $Info.PackageSettings.PortableMarkerMode | Should -Be 'Always'
    $Info.PackageSettings.PortableAllowAnyDrive | Should -BeTrue
    $Info.PackageSettings.PortableDefaultFolder | Should -Be 'DMDeployMasterKnown'
    $Info.InstallerSwitches.Silent | Should -Be '/silent'
    $Info.InstallerSwitches.InstallLocation | Should -Be '/appfolder "<INSTALLPATH>"'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/silent'
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.CommandLineSwitches.Portable | Should -Be '/portable "<PATH>"'
    $Info.CommandLineSwitches.InstallForAllUsers | Should -Be '/userall'
    $Info.CommandLineSwitches.SkipElevation | Should -Be '/noadmin'
    $Info.CommandLineSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallForCurrentUser'
    $Info.AppsAndFeaturesEntries.Count | Should -Be 1
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'DMDeployMasterKnown'
    $Info.BuiltInRegistration | Should -BeNullOrEmpty
    $Info.BuiltInRegistrationVariants.Scope | Should -Be @('user', 'user', 'machine', 'machine')
    $Info.BuiltInRegistrationVariants.Root | Should -Be @('HKCU', 'HKCU', 'HKLM', 'HKLM')
    $Info.BuiltInRegistrationVariants.Architecture | Should -Be @('x86', 'x64', 'x86', 'x64')
    $Info.ParserVersionInfo.ParserMajor | Should -Be 7
    $Info.ParserVersionInfo.FormatProfile | Should -Be 'Header74'
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
    $Files = @(Expand-DeployMasterInstaller -Path $Script:DeployMasterLegacyFixture -DestinationPath $DestinationPath -Name 'bvplay.exe' -CollisionAction Rename)

    $Info.DisplayName | Should -Be 'Brinno Video Player'
    $Info.DisplayVersion | Should -Be '1.139.00'
    $Info.ProductCode | Should -Be 'Brinno Video Player'
    $Info.Scope | Should -Be 'machine'
    $Info.ExtractedFiles.Count | Should -Be 11
    $Info.Components.Count | Should -Be 1
    $Info.InstalledFiles.Count | Should -Be 7
    $Info.Shortcuts.Count | Should -Be 2
    $Info.MinimumWindows10VersionCode | Should -Be 1507
    $Info.MaximumWindows10VersionCode | Should -Be 9999
    $Info.MinimumWindows11VersionCode | Should -BeNullOrEmpty
    $Info.MaximumWindows11VersionCode | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -BeNullOrEmpty
    $Info.BuiltInRegistration.UninstallString | Should -Be '%PROGRAMFILES%\Brinno\Brinno Video Player\UnDeploy.exe "%PROGRAMFILES%\Brinno\Brinno Video Player\Deploy.log"'
    $Files.Count | Should -Be 1
    (Get-PELayout -Path $Files[0].FullName).MachineName | Should -Be 'I386'
  }

  It 'Should treat an aligned PE certificate table as an envelope outside the logical package size' {
    $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Baseline.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster behavior fixture is not cached.'; return }
    $SignedPath = Join-Path $TestDrive 'DeployMaster-SignedEnvelope.exe'
    $Bytes = [IO.File]::ReadAllBytes($FixturePath)
    $PeOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
    $OptionalHeaderOffset = $PeOffset + 24
    $DataDirectoryOffset = $OptionalHeaderOffset + ([BitConverter]::ToUInt16($Bytes, $OptionalHeaderOffset) -eq 0x10B ? 96 : 112)
    $SecurityDirectoryOffset = $DataDirectoryOffset + 32
    $CertificateOffset = ($Bytes.Length + 7) -band -8
    $Output = [byte[]]::new($CertificateOffset + 16)
    [Array]::Copy($Bytes, $Output, $Bytes.Length)
    [BitConverter]::GetBytes([uint32]$CertificateOffset).CopyTo($Output, $SecurityDirectoryOffset)
    [BitConverter]::GetBytes([uint32]16).CopyTo($Output, $SecurityDirectoryOffset + 4)
    [BitConverter]::GetBytes([uint32]16).CopyTo($Output, $CertificateOffset)
    [BitConverter]::GetBytes([uint16]0x0200).CopyTo($Output, $CertificateOffset + 4)
    [BitConverter]::GetBytes([uint16]0x0002).CopyTo($Output, $CertificateOffset + 6)
    [IO.File]::WriteAllBytes($SignedPath, $Output)

    $Info = Get-DeployMasterInfo -Path $SignedPath
    $Info.OverlayInfo.HasSignedEnvelope | Should -BeTrue
    $Info.OverlayInfo.ExpectedFileSize | Should -Be $Bytes.Length
    $Info.OverlayInfo.CertificateOffset | Should -Be $CertificateOffset
    $Info.OverlayInfo.CertificateSize | Should -Be 16
  }

  $HistoricalProfiles = @(
    @{ Version = '6.0.1'; Profile = 'Header66'; HeaderSize = 66; FileCount = 17; Range = '6.0.1-6.1.2'; UninstallRoute = 'UnquotedExecutableQuotedLog'; HasWindows10Bounds = $false; HasUserAllSwitch = $false; HasPackageSettings = $false; HasSkipElevationSwitch = $false }
    @{ Version = '6.5.1'; Profile = 'Header70'; HeaderSize = 70; FileCount = 17; Range = '6.5.1-7.1.1'; UninstallRoute = 'UnquotedExecutableQuotedLog'; HasWindows10Bounds = $true; HasUserAllSwitch = $true; HasPackageSettings = $false; HasSkipElevationSwitch = $true }
    @{ Version = '7.1.1'; Profile = 'Header70'; HeaderSize = 70; FileCount = 17; Range = '6.5.1-7.1.1'; UninstallRoute = 'UnquotedExecutableQuotedLog'; HasWindows10Bounds = $true; HasUserAllSwitch = $true; HasPackageSettings = $false; HasSkipElevationSwitch = $true }
    @{ Version = '7.2.0'; Profile = 'Header74'; HeaderSize = 74; FileCount = 21; Range = '7.2.0-7.7.0'; UninstallRoute = 'QuotedExecutableAndLog'; HasWindows10Bounds = $true; HasUserAllSwitch = $true; HasPackageSettings = $true; HasSkipElevationSwitch = $true }
    @{ Version = '7.6.0'; Profile = 'Header74'; HeaderSize = 74; FileCount = 21; Range = '7.2.0-7.7.0'; UninstallRoute = 'QuotedExecutableAndLog'; HasWindows10Bounds = $true; HasUserAllSwitch = $true; HasPackageSettings = $true; HasSkipElevationSwitch = $true }
  )
  It 'Should classify archived signed runtime <Version> with the <Profile> structural profile' -ForEach $HistoricalProfiles {
    $FixturePath = Join-Path (Join-Path $Script:DeployMasterHistoricalFixtureDirectory $Version) 'SetupDeployMasterDemo.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because "The archived DeployMaster $Version fixture is not cached."; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.OverlayInfo.FormatProfile | Should -Be $Profile
    $Info.OverlayInfo.FormatVersion | Should -Be $Profile
    $Info.OverlayInfo.HeaderSize | Should -Be $HeaderSize
    $Info.OverlayInfo.ObservedRuntimeRange | Should -Be $Range
    $Info.OverlayInfo.HasSignedEnvelope | Should -BeTrue
    $Info.FileEntries.Count | Should -Be $FileCount
    if ($HasPackageSettings) {
      $Info.PackageSettings.PortableInstallationMode | Should -Be 'Never'
    } else {
      $Info.PackageSettings | Should -BeNullOrEmpty
    }
    $Info.CommandLineSwitches.Portable | Should -BeNullOrEmpty
    $Info.CommandLineSwitches.InstallForAllUsers | Should -Be ($HasUserAllSwitch ? '/userall' : $null)
    $Info.CommandLineSwitches.SkipElevation | Should -Be ($HasSkipElevationSwitch ? '/noadmin' : $null)
    $Info.CommandLineSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallForCurrentUser'
    $Info.OverlayInfo.UninstallCommandRoute | Should -Be $UninstallRoute
    $Info.BuiltInRegistrationVariants.Count | Should -Be 4
    $Info.BuiltInRegistrationVariants.Architecture | Sort-Object -Unique | Should -Be @('x64', 'x86')
    @($Info.BuiltInRegistrationVariants | Where-Object Architecture -EQ 'x86').UninstallerPath | Should -Match 'UnDeploy\.exe$'
    @($Info.BuiltInRegistrationVariants | Where-Object Architecture -EQ 'x64').UninstallerPath | Should -Match 'UnDeploy64\.exe$'
    if ($UninstallRoute -eq 'QuotedExecutableAndLog') { @($Info.BuiltInRegistrationVariants.UninstallString | Where-Object { $_ -notmatch '^".+" ".+"$' }).Count | Should -Be 0 }
    else { @($Info.BuiltInRegistrationVariants.UninstallString | Where-Object { $_ -notmatch '^[^"].+\.exe ".+\.log"$' }).Count | Should -Be 0 }
    if ($HasWindows10Bounds) {
      $Info.MinimumWindows10VersionCode | Should -Not -BeNullOrEmpty
    } else {
      $Info.MinimumWindows10VersionCode | Should -BeNullOrEmpty
      $Info.MaximumWindows10VersionCode | Should -BeNullOrEmpty
    }
  }

  It 'Should extract a metadata-resident payload from the 6.0 catalog' {
    $FixturePath = Join-Path (Join-Path $Script:DeployMasterHistoricalFixtureDirectory '6.0.1') 'SetupDeployMasterDemo.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The archived DeployMaster 6.0.1 fixture is not cached.'; return }
    $Files = @(Expand-DeployMasterInstaller -Path $FixturePath -DestinationPath (Join-Path $TestDrive 'DeployMaster60') -Name 'README.txt' -CollisionAction Rename)

    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 9081
    (Get-DumplingsTestFixtureHash -Path $Files[0].FullName) | Should -Be 'FB312CA3C34AE953BDE1730FB8E91ED1270E78914C1938E89489CAC02445043D'
  }

  It 'Should decode the 6.0 registry and form-feed association routes' {
    $FixturePath = Join-Path (Join-Path $Script:DeployMasterHistoricalFixtureDirectory '6.0.1') 'SetupDeployMasterDemo.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The archived DeployMaster 6.0.1 fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.Components.Count | Should -Be 6
    $Info.InstalledFiles.Count | Should -Be 11
    $Info.FileExtensions | Should -Be @('deploy')
    $Info.FileAssociations[0].CreateByDefault | Should -BeNullOrEmpty
    @($Info.RegistryWrites | Where-Object Evidence -EQ 'DeployMaster legacy registry operation stream').Count | Should -Be 2
    $Info.RegistryWrites.Name | Should -Contain 'UserData'
    $Info.RegistryWrites.Key | Should -Contain 'Software\Microsoft\Windows\CurrentVersion\App Paths\DeployMaster.exe'
    $Info.UnresolvedFields | Should -Not -Contain 'RegistryWrites'
    $Info.Diagnostics.Message | Should -Not -Match 'behavioral metadata stream was not fully decoded'
  }

  It 'Should preserve duplicate architecture-specific support DLL names in the current file catalog' {
    $FixturePath = Join-Path (Join-Path $Script:DeployMasterHistoricalFixtureDirectory '7.6.0') 'SetupDeployMasterDemo.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The archived DeployMaster 7.6.0 fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.FileEntries.Count | Should -Be 21
    @($Info.FileEntries | Where-Object Name -EQ 'InstallDemo.dll').Count | Should -Be 2
    $Info.Components.Count | Should -Be 6
    $Info.InstalledFiles.Count | Should -Be 15
    @($Info.Diagnostics | Where-Object Message -Like '*file-name and offset table counts differ*').Count | Should -Be 0
  }

  It 'Should reconstruct the current built-in ARP and deployment-log registration' {
    $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Baseline.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster behavior fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath
    $Registration = $Info.BuiltInRegistration

    $Registration.Scope | Should -Be 'machine'
    $Registration.Root | Should -Be 'HKLM'
    $Registration.RegistryView | Should -Be '32-bit'
    $Registration.UninstallKey | Should -Be 'Software\Microsoft\Windows\CurrentVersion\Uninstall\DMDeployMasterKnown'
    $Registration.UninstallerPath | Should -Be '%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown\UnDeploy.exe'
    $Registration.DeploymentLogPath | Should -Be '%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown\Deploy.log'
    $Registration.UninstallString | Should -Be '"%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown\UnDeploy.exe" "%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown\Deploy.log"'
    $Registration.QuietUninstallString | Should -BeNullOrEmpty
    $Registration.NoModify | Should -BeTrue
    $Registration.NoRepair | Should -BeTrue
    $Registration.VersionMajor | Should -Be '12'
    $Registration.VersionMinor | Should -Be '34'
    $Registration.RuntimeGeneratedValueNames | Should -Be @('EstimatedSize', 'InstallDate', 'Stub')
    @($Registration.RegistryWrites | Where-Object Name -EQ 'NoModify')[0].Type | Should -Be 'REG_DWORD'
    $Registration.DeploymentTrackingWrite.Key | Should -Be 'Software\JGsoft\DeployIT'
    $Info.RegistryWrites.Count | Should -Be 10
  }

  It 'Should map structured publisher and application URLs to their runtime ARP values' {
    $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'UrlArp.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster URL fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath
    $Registration = $Info.BuiltInRegistration

    $Info.HelpLink | Should -Be 'https://product.example.invalid/home'
    $Info.URLInfoUpdate | Should -Be 'https://product.example.invalid/home'
    $Info.URLInfoAbout | Should -Be 'https://publisher.example.invalid/support'
    $Registration.HelpLink | Should -Be $Info.HelpLink
    $Registration.URLInfoUpdate | Should -Be $Info.URLInfoUpdate
    $Registration.URLInfoAbout | Should -Be $Info.URLInfoAbout
    @($Registration.RegistryWrites | Where-Object Name -EQ 'HelpLink')[0].Value | Should -Be $Info.HelpLink
    @($Registration.RegistryWrites | Where-Object Name -EQ 'URLInfoUpdate')[0].Value | Should -Be $Info.URLInfoUpdate
    @($Registration.RegistryWrites | Where-Object Name -EQ 'URLInfoAbout')[0].Value | Should -Be $Info.URLInfoAbout
  }

  It 'Should fall back to the publisher URL for HelpLink on locator-based media without an application URL' {
    InModuleScope DeployMaster {
      $Identity = [pscustomobject]@{
        DisplayName = 'DMDeployMasterKnown'; DisplayVersion = '12.34.56'; Publisher = 'Dumplings Parser Lab'
        PackageUrl = $null; PublisherUrl = 'https://publisher.example.invalid/support'; SupportsDualScope = $false
      }
      foreach ($Case in @(
          @{ HeaderSize = 74; Route = 'QuotedExecutableAndLog' }
          @{ HeaderSize = 70; Route = 'UnquotedExecutableQuotedLog' }
        )) {
        $Header = [pscustomobject]@{ ApplicationArchitectureMode = 'x86ApplicationForX86AndX64Windows'; UninstallCommandRoute = $Case.Route; HeaderSize = $Case.HeaderSize }
        $PackageData = [pscustomobject]@{ Identity = $Identity; Header = $Header }
        $Registration = Get-DeployMasterBuiltInRegistration -PackageData $PackageData -Scope 'machine' -InstallLocation '%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown' -RegistryView '32-bit' -TargetArchitecture 'x86'
        $Registration.HelpLink | Should -Be 'https://publisher.example.invalid/support'
        $Registration.URLInfoUpdate | Should -Be 'https://publisher.example.invalid/support'
        $Registration.URLInfoAbout | Should -Be 'https://publisher.example.invalid/support'

        $Identity.PackageUrl = 'https://product.example.invalid/home'
        $Registration = Get-DeployMasterBuiltInRegistration -PackageData $PackageData -Scope 'machine' -InstallLocation '%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown' -RegistryView '32-bit' -TargetArchitecture 'x86'
        $Registration.HelpLink | Should -Be 'https://product.example.invalid/home'
        $Registration.URLInfoAbout | Should -Be 'https://publisher.example.invalid/support'
        $Identity.PackageUrl = $null
      }
    }
  }

  It 'Should expose the runtime URL fallback through the top-level parser contract' {
    $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Baseline.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster behavior fixture is not cached.'; return }

    $Info = Get-DeployMasterInfo -Path $FixturePath
    $Info.PackageUrl | Should -BeNullOrEmpty
    $Info.HelpLink | Should -Be $Info.PublisherUrl
    $Info.URLInfoUpdate | Should -Be $Info.PublisherUrl
    $Info.URLInfoAbout | Should -Be $Info.PublisherUrl
  }

  It 'Should split non-numeric display versions into string version components' {
    InModuleScope DeployMaster {
      $Identity = [pscustomobject]@{
        DisplayName = 'DMDeployMasterKnown'; DisplayVersion = 'DEMO 6.1.2'; Publisher = 'Dumplings Parser Lab'
        PackageUrl = $null; PublisherUrl = 'https://publisher.example.invalid/support'; SupportsDualScope = $false
      }
      $Header = [pscustomobject]@{ ApplicationArchitectureMode = 'x86ApplicationForX86AndX64Windows'; UninstallCommandRoute = 'UnquotedExecutableQuotedLog'; HeaderSize = 70 }
      $Registration = Get-DeployMasterBuiltInRegistration -PackageData ([pscustomobject]@{ Identity = $Identity; Header = $Header }) -Scope 'machine' -InstallLocation '%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown' -RegistryView '32-bit' -TargetArchitecture 'x86'
      $Registration.VersionMajor | Should -Be 'DEMO 6'
      $Registration.VersionMinor | Should -Be '1'
      @($Registration.RegistryWrites | Where-Object Name -EQ 'VersionMajor')[0].Value | Should -Be 'DEMO 6'
    }
  }

  It 'Should decode file overwrite and uninstall-retention policies' {
    $Cases = @(
      @{ Name = 'FilePolicy0.exe'; Behavior = 'AlwaysOverwrite'; NeverUninstall = $false }
      @{ Name = 'Baseline.exe'; Behavior = 'OverwriteIfNewer'; NeverUninstall = $false }
      @{ Name = 'FilePolicy2.exe'; Behavior = 'NeverOverwrite'; NeverUninstall = $false }
      @{ Name = 'NeverUninstall.exe'; Behavior = 'NeverOverwrite'; NeverUninstall = $true }
    )
    foreach ($Case in $Cases) {
      $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory $Case.Name
      if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because "The controlled DeployMaster $($Case.Name) fixture is not cached."; return }
      $File = (Get-DeployMasterInfo -Path $FixturePath).InstalledFiles[0]
      $File.OverwriteBehavior | Should -Be $Case.Behavior
      $File.NeverUninstall | Should -Be $Case.NeverUninstall
    }
  }

  It 'Should decode x86 and x64 file applicability independently' {
    foreach ($Case in @(
        @{ Name = 'FileArchX86Binary.exe'; Architectures = @('x86') }
        @{ Name = 'FileArchX64Binary.exe'; Architectures = @('x64') }
      )) {
      $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory $Case.Name
      if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because "The controlled DeployMaster $($Case.Name) fixture is not cached."; return }
      $File = (Get-DeployMasterInfo -Path $FixturePath).InstalledFiles[0]
      $File.Included | Should -BeTrue
      $File.Architectures | Should -Be $Case.Architectures
    }
  }

  It 'Should suppress normal-install ARP evidence for always-portable current media' {
    $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Baseline.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster behavior fixture is not cached.'; return }
    $MutablePath = Join-Path $TestDrive 'DeployMaster-AlwaysPortable.exe'
    Copy-Item -LiteralPath $FixturePath -Destination $MutablePath

    InModuleScope DeployMaster -Parameters @{ MutablePath = $MutablePath } {
      $Stream = [IO.File]::Open($MutablePath, 'Open', 'ReadWrite', 'None')
      try {
        $PackageData = Read-DeployMasterPackageData -Stream $Stream
        $Stream.Position = $PackageData.IdentityBlock.EndOffset + 2
        $Stream.WriteByte(2)
        $Stream.Flush()
        $IntegrityStream = New-BoundedReadStream -Stream $Stream -Offset $PackageData.Locator.PackageOffset -Length $PackageData.Locator.IntegrityLength -LeaveOpen
        try { $Crc32 = [uint32](Get-BinaryCrc32 -Stream $IntegrityStream -MaximumBytes $PackageData.Locator.IntegrityLength) }
        finally { $IntegrityStream.Dispose() }
        $Stream.Position = 0x88
        $CrcBytes = [BitConverter]::GetBytes($Crc32)
        $Stream.Write($CrcBytes, 0, $CrcBytes.Length)
      } finally { $Stream.Dispose() }
    }

    $Info = Get-DeployMasterInfo -Path $MutablePath
    $Info.PackageSettings.PortableInstallationMode | Should -Be 'Always'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $Info.BuiltInRegistrationVariants | Should -BeNullOrEmpty
    $Info.RegistryWrites | Should -BeNullOrEmpty
    $Info.InstallerSwitches.InstallLocation | Should -Be '/portable "<INSTALLPATH>"'
    $Info.CommandLineSwitches.Portable | Should -Be '/portable "<PATH>"'
    @($Info.Diagnostics | Where-Object Id -EQ 'DeployMaster.Metadata.PortableOnlyNoArp').Count | Should -Be 1
  }

  It 'Should decode explicit Registry-tab writes and project uninstall evidence' {
    InModuleScope DeployMaster {
      function AddString([Collections.Generic.List[byte]]$Buffer, [string]$Value) {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Buffer.AddRange([BitConverter]::GetBytes([uint16]$Encoded.Length))
        $Buffer.AddRange($Encoded)
      }

      $Bytes = [Collections.Generic.List[byte]]::new()
      $Bytes.Add(1)
      AddString $Bytes 'HKEY_LOCAL_MACHINE'
      foreach ($Key in 'Software', 'Microsoft', 'Windows', 'CurrentVersion', 'Uninstall', 'Custom.Product') {
        $Bytes.Add(1)
        AddString $Bytes $Key
      }
      foreach ($Pair in @(
          @('DisplayName', 'Custom Product'),
          @('DisplayVersion', '1.2.3'),
          @('Publisher', 'Example Publisher')
        )) {
        $Bytes.Add(4)
        AddString $Bytes $Pair[0]
        $Bytes.Add(7)
        AddString $Bytes $Pair[1]
      }
      1..8 | ForEach-Object { $Bytes.Add(0xFF) }

      $Registry = ConvertFrom-DeployMasterRegistryBlock -Bytes $Bytes.ToArray() -ScopeValue 1
      $Registry.RegistryWrites.Count | Should -Be 3
      $Registry.RegistryWrites.Type | Should -Be @('REG_SZ', 'REG_SZ', 'REG_SZ')
      $Entry = @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $Registry.RegistryWrites)
      $Entry.Count | Should -Be 1
      $Entry[0].ProductCode | Should -Be 'Custom.Product'
      $Entry[0].DisplayName | Should -Be 'Custom Product'
      $Entry[0].DisplayVersion | Should -Be '1.2.3'
      $Entry[0].Publisher | Should -Be 'Example Publisher'
    }
  }

  It 'Should merge explicit ARP overrides and exclude hidden entries' {
    InModuleScope DeployMaster {
      $BuiltIn = [pscustomobject]@{ ProductCode = 'Product'; DisplayName = 'Built-in'; DisplayVersion = '1'; Publisher = 'Publisher'; InstallerType = 'exe' }
      $Explicit = [pscustomobject]@{ ProductCode = 'product'; DisplayName = 'Explicit'; DisplayVersion = '2'; InstallerType = 'exe' }
      $Merged = @(Merge-DeployMasterAppsAndFeaturesEntry -Entry @($BuiltIn, $Explicit))
      $Merged.Count | Should -Be 1
      $Merged[0].DisplayName | Should -Be 'Explicit'
      $Merged[0].DisplayVersion | Should -Be '2'
      $Merged[0].Publisher | Should -Be 'Publisher'

      $HiddenWrites = @(
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'DisplayName'; Value = 'Hidden Product'; Type = 'REG_SZ'; OnlyIfMissing = $false },
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'SystemComponent'; Value = [uint32]1; Type = 'REG_DWORD'; OnlyIfMissing = $false }
      )
      @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $HiddenWrites) | Should -BeNullOrEmpty
    }
  }

  It 'Should parse bare-CR prerequisite descriptors without losing positional fields' {
    InModuleScope DeployMaster {
      $Descriptor = ConvertFrom-DeployMasterTextBlock -Bytes ([Text.Encoding]::UTF8.GetBytes("framework.exe`rhttps://example.invalid/framework.exe`r"))
      $Requirement = ConvertFrom-DeployMasterDotNetFrameworkRecord -Flags 0x23 -VersionCode 11 -Descriptor $Descriptor -RawValues ([byte[]]::new(16))

      $Descriptor.Fields | Should -Be @('framework.exe', 'https://example.invalid/framework.exe', '')
      $Requirement.CompatibleVersions | Should -Be @('1.0', '1.1', '4.8.1+')
      $Requirement.Minimum4xVersion | Should -Be '4.8.1'
      $Requirement.InstallerFileName | Should -Be 'framework.exe'
      $Requirement.HasAutomaticInstaller | Should -BeTrue
      $Requirement.DownloadUrl | Should -Be 'https://example.invalid/framework.exe'
      $Requirement.UnknownFlags | Should -Be 0
    }
  }

  It 'Should decode the controlled DeployMaster .NET Framework prerequisite' {
    $FixturePath = Join-Path $Script:DeployMasterOptionFixtureDirectory 'Net40Bundled.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster .NET prerequisite fixture is not cached.'; return }
    $Requirement = (Get-DeployMasterInfo -Path $FixturePath).DotNetFrameworkRequirement

    $Requirement.CompatibleVersions | Should -Be @('4.0+')
    $Requirement.Requires4x | Should -BeTrue
    $Requirement.Minimum4xVersion | Should -Be '4.0'
    $Requirement.InstallerFileName | Should -Be 'DeployMasterCmd.exe'
    $Requirement.HasAutomaticInstaller | Should -BeTrue
    $Requirement.DownloadUrl | Should -Be 'https://example.invalid/dotnet.exe'
  }

  It 'Should distinguish an elevated current-user package from machine scope' {
    $FixturePath = Join-Path $Script:DeployMasterOptionFixtureDirectory 'UserRequireAdmin.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled elevated-user DeployMaster fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.Scope | Should -Be 'user'
    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.RequiresAdministrativeRights | Should -BeTrue
    $Info.DefaultInstallLocation | Should -Be '%LOCALAPPDATA%\Dumplings Parser Lab\DMDeployMasterKnown'
    $Info.UserInstallLocation | Should -Be '%LOCALAPPDATA%\Dumplings Parser Lab\DMDeployMasterKnown'
    $Info.RawUserInstallLocation | Should -Be '%LOCALAPPDATAROOT%\Dumplings Parser Lab\DMDeployMasterKnown'
    $Info.MachineInstallLocation | Should -Be '%PROGRAMFILES%\Dumplings Parser Lab\DMDeployMasterKnown'
    $Info.RegistryWrites[0].Root | Should -Be 'HKCU'
    $Info.BuiltInRegistration.Root | Should -Be 'HKCU'
    $Info.BuiltInRegistration.UninstallString | Should -Be '"%LOCALAPPDATA%\Dumplings Parser Lab\DMDeployMasterKnown\UnDeploy.exe" "%LOCALAPPDATA%\Dumplings Parser Lab\DMDeployMasterKnown\Deploy.log"'
    $Info.BuiltInRegistration.DeploymentTrackingWrite.Root | Should -Be 'HKCU'
    $Info.Diagnostics.Message | Should -Not -Contain 'The DeployMaster identity scope marker does not match the package-control scope byte.'
  }

  It 'Should decode current Windows platform constraints from the control header' {
    $FixturePath = Join-Path $Script:DeployMasterFixtureDirectory 'KnownSetup.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster platform fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.SupportedWindowsVersions | Should -Be @('Windows7', 'Windows8', 'Windows8.1', 'Windows10', 'Windows11')
    $Info.SupportsFutureWindowsVersions | Should -BeTrue
    $Info.MinimumWindows10VersionCode | Should -Be 1507
    $Info.MaximumWindows10VersionCode | Should -Be 9999
    $Info.MinimumWindows11VersionCode | Should -Be 2110
    $Info.MaximumWindows11VersionCode | Should -Be 9999
  }

  It 'Should parse the compiled final expiration date without guessing the builder source mode' {
    $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'ExpireDays.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster expiration fixture is not cached.'; return }
    $Info = Get-DeployMasterInfo -Path $FixturePath

    $Info.ExpirationPolicy.IsTimeLimited | Should -BeTrue
    $Info.ExpirationPolicy.ExpirationDate | Should -Be ([datetime]'2026-10-05')
    $Info.ExpirationPolicy.SourceMode | Should -Be 'CompiledFinalDate'
    $Info.ExpirationPolicy.Message | Should -Match 'installer expired on 2026/10/5'
    @($Info.Diagnostics | Where-Object Id -EQ 'DeployMaster.Installability.TimeLimited').Count | Should -Be 1

    $Baseline = Get-DeployMasterInfo -Path (Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Baseline.exe')
    $Baseline.ExpirationPolicy.IsTimeLimited | Should -BeFalse
    $Baseline.ExpirationPolicy.ExpirationDate | Should -BeNullOrEmpty
  }

  It 'Should decode controlled update and running-application policies' {
    foreach ($Case in @(
        @{ Name = 'DeleteObsolete.exe'; Flag = 1; Property = 'DeleteObsoleteFiles'; Value = $true },
        @{ Name = 'PatchMessage.exe'; Flag = 2; Property = 'RequiresPreviousRelease'; Value = $true },
        @{ Name = 'WindowClass.exe'; Flag = 4; Property = 'BlockedWindowClasses'; Value = @('DMParserWindowClass') },
        @{ Name = 'WindowCaption.exe'; Flag = 8; Property = 'BlockedWindowCaptions'; Value = @('DM Parser Caption') }
      )) {
      $FixturePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory $Case.Name
      if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster update-policy fixtures are not cached.'; return }
      $Policy = (Get-DeployMasterInfo -Path $FixturePath).UpdatePolicy
      $Policy.Flags | Should -Be $Case.Flag
      $Policy.($Case.Property) | Should -Be $Case.Value
    }

    $Patch = (Get-DeployMasterInfo -Path (Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'PatchMessage.exe')).UpdatePolicy
    $Patch.IsPatchPackage | Should -BeTrue
    $Patch.RequiredReleaseDate | Should -Be ([datetime]'2026-07-13')
    $Patch.PatchRequirementLines | Should -Be @('A previous 12.34 release is required.', 'Download the full installer first.')
  }

  It 'Should distinguish readme, license, and support-DLL catalog entries' {
    $ReadmePath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'Readme.exe'
    $SupportPath = Join-Path $Script:DeployMasterBehaviorFixtureDirectory 'SupportDll.exe'
    if (-not (Test-Path -LiteralPath $ReadmePath) -or -not (Test-Path -LiteralPath $SupportPath)) { Set-ItResult -Skipped -Because 'The controlled DeployMaster support-file fixtures are not cached.'; return }

    $Readme = Get-DeployMasterInfo -Path $ReadmePath
    $Readme.ReadmeFileName | Should -Be 'payload.txt'
    $Readme.LicenseFileName | Should -Be 'license.txt'
    $Readme.FileEntries.Name | Should -Contain 'payload.txt'
    $Readme.FileEntries.Name | Should -Contain 'license.txt'

    $Support = Get-DeployMasterInfo -Path $SupportPath
    $Support.SupportDlls.Count | Should -Be 1
    $Support.SupportDlls[0].Architecture | Should -Be 'x86'
    $Support.SupportDlls[0].FileName | Should -Be 'version.dll'
    $Support.FileEntries.Name | Should -Contain 'version.dll'
    $Support.UnresolvedFields | Should -Contain 'SupportDllEffects'
    @($Support.Diagnostics | Where-Object Id -EQ 'DeployMaster.Installability.SupportDllEffectsOpaque').Count | Should -Be 1

    $ExtractedSupportDll = @(Expand-DeployMasterInstaller -Path $SupportPath -DestinationPath (Join-Path $TestDrive 'SupportDll') -Name 'Payload/version.dll' -CollisionAction Rename)
    $ExtractedSupportDll.Count | Should -Be 1
    (Get-PEArchitectureInfo -Path $ExtractedSupportDll[0].FullName).FileKind | Should -Be 'Dll'
  }
}
