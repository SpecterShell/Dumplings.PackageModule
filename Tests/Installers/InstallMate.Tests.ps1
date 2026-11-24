. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive
  $Script:InstallMateFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\InstallMate\11\KnownScenarios'
  $Script:InstallMateLegacyFixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'PoP8Setup.exe')
  $Script:InstallMateWaybackDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\InstallMate\Wayback'
  $Script:InstallMateRecordFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\InstallMate\11\RecordScenarios'
  $Script:InstallMateServiceControlFixtureDirectory = Join-Path $Script:InstallMateRecordFixtureDirectory 'ServiceControls'
  $Script:InstallMate94Fixture = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\InstallMate\9.4.1\tin94.exe'
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

  It 'Should reject unmapped tin file-record revisions for extraction' {
    InModuleScope InstallMate {
      (Test-InstallMateFileLayoutSupported -DatabaseSignature tin3 -FormatMajor 2) | Should -BeTrue
      (Test-InstallMateFileLayoutSupported -DatabaseSignature tin5 -FormatMajor 2) | Should -BeTrue
      (Test-InstallMateFileLayoutSupported -DatabaseSignature tin5 -FormatMajor 3) | Should -BeFalse
      (Test-InstallMateFileLayoutSupported -DatabaseSignature tin5 -FormatMajor 6) | Should -BeFalse
      (Test-InstallMateFileLayoutSupported -DatabaseSignature tin5 -FormatMajor 7) | Should -BeTrue
      (Test-InstallMateFileLayoutSupported -DatabaseSignature tin9 -FormatMajor 114) | Should -BeTrue
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
    $Info.ProductCodeEvidence | Should -Be 'Typed tin symbol record and resolved UninstallKey'
  }

  It 'Should parse and expand the legacy TIZ1 Setup.ini route' {
    $FixturePath = Join-Path $Script:InstallMateWaybackDirectory '20021206025851-tin2.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The InstallMate 2.25 Wayback fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'installmate-tiz1'
    $Info = Get-InstallMateInfo -Path $FixturePath
    $Files = @(Expand-InstallMateInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'Readme.rtf' -CollisionAction Rename)

    $Info.ArchiveInfo.Signature | Should -Be 'tiz1'
    $Info.ArchiveInfo.CompressionAlgorithm | Should -Be 'Zlib'
    $Info.DatabaseInfo.Signature | Should -Be 'Setup.ini'
    $Info.DatabaseInfo.FileRecordCount | Should -Be 17
    $Info.DisplayName | Should -Be 'Tarma Installer'
    $Info.DisplayVersion | Should -Be '2.25.1042'
    $Info.Publisher | Should -Be 'Tarma Software Research Pty Ltd'
    $Info.ProductCode | Should -Be 'Tarma Installer'
    $Info.ProductCodeEvidence | Should -Be 'Setup.ini uninstall-key value'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Tarma Installer'
    $Files.Count | Should -Be 1
    $Files[0].FullName | Should -Be (Join-Path $DestinationPath 'Readme.rtf')
    $Files[0].Length | Should -Be 8179
    (Get-DumplingsTestFixtureHash -Path $Files[0].FullName) | Should -Be 'BC5BD620007DA585FF182F83628A87BB275BA584B270D37D95FF2A1BA61B2EE9'
  }

  It 'Should resolve legacy symbol-backed uninstall identity' {
    $FixturePath = Join-Path $Script:InstallMateWaybackDirectory '20060819142855-tin2.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The InstallMate 2.99 Wayback fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Info.DisplayName | Should -Be 'Tarma® QuickInstall'
    $Info.ProductCode | Should -Be 'Tarma® QuickInstall'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Tarma QuickInstall'
    $Info.DatabaseInfo.FileRecordCount | Should -Be 53
  }

  It 'Should use generation-specific tin3 and early tin5 file layouts' {
    $Tin3Path = Join-Path $Script:InstallMateWaybackDirectory '20060819143029-tin3.exe'
    $Tin5Path = Join-Path $Script:InstallMateWaybackDirectory '20080719163731-tin5.exe'
    if (-not (Test-Path -LiteralPath $Tin3Path) -or -not (Test-Path -LiteralPath $Tin5Path)) { Set-ItResult -Skipped -Because 'The InstallMate 3.2 or 5.2 Wayback fixture is not cached.'; return }
    $Tin3 = Get-InstallMateInfo -Path $Tin3Path
    $Tin5 = Get-InstallMateInfo -Path $Tin5Path

    $Tin3.ArchiveInfo.BuilderFormatVersion | Should -Be '3.2'
    $Tin3.DatabaseInfo.Signature | Should -Be 'tin3'
    $Tin3.DatabaseInfo.FileRecordCount | Should -Be 134
    $Tin3.ProductCode | Should -Be '{760C70C3-ABE2-4F51-89D3-0FA2C43E8F51}'
    $Tin5.ArchiveInfo.BuilderFormatVersion | Should -Be '5.2'
    $Tin5.DatabaseInfo.Signature | Should -Be 'tin5'
    $Tin5.DatabaseInfo.FileRecordCount | Should -Be 163
    $Tin5.ProductCode | Should -Be '{C27A4272-6AC0-49FD-B82E-B60824FC8B62}'
  }

  It 'Should select the package database after a concatenated loader archive' {
    $FixturePath = Join-Path $Script:InstallMateWaybackDirectory '20100114225226-tin5.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The InstallMate 5.7 concatenated-archive fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'installmate-concatenated'
    $Info = Get-InstallMateInfo -Path $FixturePath
    $Files = @(Expand-InstallMateInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name '*StandardFolders32.xml' -CollisionAction Rename)

    $Info.ArchiveInfo.ArchiveOffset | Should -Be 168805
    $Info.ArchiveInfo.ArchiveCandidates.Count | Should -Be 2
    @($Info.ArchiveInfo.ArchiveCandidates | Where-Object IsPackageArchive).Count | Should -Be 1
    $Info.DatabaseInfo.FileRecordCount | Should -Be 214
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 1824
    (Get-DumplingsTestFixtureHash -Path $Files[0].FullName) | Should -Be '47DDE5C44F12A79B365A82FBB71DD296ED8321E7F7C2E70590286C77660317E6'
  }

  It 'Should decode a section-hosted TIZ4 LZMA2 package' {
    $FixturePath = Join-Path $Script:InstallMateWaybackDirectory '20230117131628-tin9.114.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The InstallMate 9.114 TIZ4 fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'installmate-tiz4'
    $Info = Get-InstallMateInfo -Path $FixturePath
    $Files = @(Expand-InstallMateInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name '*/Resources.xml' -CollisionAction Rename)

    $Info.ArchiveInfo.ContainerRoute | Should -Be 'Section:.tsuarch'
    $Info.ArchiveInfo.Signature | Should -Be 'tiz4'
    $Info.ArchiveInfo.CompressionAlgorithm | Should -Be 'Lzma2'
    $Info.ArchiveInfo.BuilderFormatVersion | Should -Be '9.114'
    $Info.DatabaseInfo.Signature | Should -Be 'tin9'
    $Info.DatabaseInfo.FileRecordCount | Should -Be 385
    $Info.ProductCode | Should -Be '{0A5E841E-2675-46A1-8F43-ED59D58C8339}'
    @($Info.Components | Where-Object Name -CEQ 'Product').Count | Should -Be 1
    @($Info.Components | Where-Object Name -CEQ 'Product')[0].DescriptionTranslationCount | Should -Be 1
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 2711
    (Get-DumplingsTestFixtureHash -Path $Files[0].FullName) | Should -Be '78DC4B88C418EF2765AA1748BBCAF48578A95093EEC816F7B0DEDB2131A76A65'
  }

  It 'Should decode the InstallMate 9 Loader + Download install record' {
    $FixturePath = Join-Path $Script:InstallMateWaybackDirectory '20140211010128-tin3.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The InstallMate 9.10 Loader + Download fixture is not cached.'; return }
    Get-DumplingsTestFixtureHash -Path $FixturePath | Should -Be '59B2C39D2F68C5AB073C56E61A8302CE61DF1A33EA1C8DE30E5A7591777A4D65'

    $Info = Get-InstallMateInfo -Path $FixturePath
    $Info.InstallLevel | Should -Be 4
    $Info.InstallLevelName | Should -Be 'AllUsers'
    $Info.Scope | Should -Be 'machine'
    $Info.PackageDownloadUrl | Should -Be 'http://www.installmate.com/download/tiz9'
    @($Info.Diagnostics.Id) | Should -Not -Contain 'InstallMate.Scope.GenerationUnmapped'
  }

  It 'Should retain translated product-component metadata in InstallMate 9.4' {
    if (-not (Test-Path -LiteralPath $Script:InstallMate94Fixture)) { Set-ItResult -Skipped -Because 'The official InstallMate 9.4 fixture is not cached.'; return }
    Get-DumplingsTestFixtureHash -Path $Script:InstallMate94Fixture | Should -Be '809B116772289DF9EC1620A8A5EB22D6E79EC40856E905EE1A1C82B620AE69DA'

    $Info = Get-InstallMateInfo -Path $Script:InstallMate94Fixture
    $ProductComponent = @($Info.Components | Where-Object Name -CEQ 'Product')
    $ProductComponent.Count | Should -Be 1
    $ProductComponent[0].Description | Should -Be 'This installs <ProductName>'
    $ProductComponent[0].DescriptionTranslationCount | Should -Be 1
    $Info.InstallLevel | Should -Be 4
    @($Info.Diagnostics.Id) | Should -Not -Contain 'InstallMate.Scope.GenerationUnmapped'
  }

  It 'Should decode the controlled TIZ2 Zlib package route' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'Compressor1.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate TIZ2 fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Info.ArchiveInfo.Signature | Should -Be 'tiz2'
    $Info.ArchiveInfo.CompressionAlgorithm | Should -Be 'Zlib'
    $Info.ArchiveInfo.PropertiesLength | Should -Be 0
    ($Info.ArchiveInfo.DataOffset - $Info.ArchiveInfo.ArchiveOffset) | Should -Be 0x38
    $Info.DatabaseInfo.Signature | Should -Be 'tinB'
    $Info.CanExpand | Should -BeTrue
    $Info.ParserVersionInfo.ParserMajor | Should -Be 6
  }

  It 'Should decode and expand a payload-bearing TIZ2 Zlib package' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'Tiz2Payload.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled payload-bearing InstallMate TIZ2 fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'installmate-tiz2-payload'
    $Info = Get-InstallMateInfo -Path $FixturePath
    $Files = @(Expand-InstallMateInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'Payload.txt' -CollisionAction Rename)

    $Info.ArchiveInfo.Signature | Should -Be 'tiz2'
    $Info.ArchiveInfo.CompressionAlgorithm | Should -Be 'Zlib'
    $Info.DatabaseInfo.Signature | Should -Be 'tinB'
    $Info.FileEntries.Count | Should -Be 1
    $Info.FileEntries[0].FileName | Should -Be 'Payload.txt'
    $Info.FileEntries[0].RelativePath | Should -Be 'Payload.txt'
    $Info.FileEntries[0].UncompressedSize | Should -Be 33
    $Info.Diagnostics.Count | Should -Be 0
    $Files.Count | Should -Be 1
    $Files[0].FullName | Should -Be (Join-Path $DestinationPath 'Payload.txt')
    $Files[0].Length | Should -Be 33
    (Get-DumplingsTestFixtureHash -Path $Files[0].FullName) | Should -Be '14071B8BA9AE8615E725A32DAC26F81A3D680546D450872CF758345F02A45708'
  }

  It 'Should resolve the current component and folder graph' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'Folder.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate folder fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath
    $Folder = @($Info.Folders | Where-Object Name -CEQ 'ResearchFolder')

    $Folder.Count | Should -Be 1
    $Folder[0].PathSegment | Should -Be 'Research Folder'
    $Folder[0].ResolvedPath | Should -Be '%ProgramFiles%\Product name\Research Folder'
  }

  It 'Should decode current registry, environment, shortcut, and execution records' {
    $RegistryPath = Join-Path $Script:InstallMateRecordFixtureDirectory 'Registry.exe'
    $EnvironmentPath = Join-Path $Script:InstallMateRecordFixtureDirectory 'Environment.exe'
    $ShortcutPath = Join-Path $Script:InstallMateRecordFixtureDirectory 'Shortcut.exe'
    $ExecutionPath = Join-Path $Script:InstallMateRecordFixtureDirectory 'Execution.exe'
    if (@(@($RegistryPath, $EnvironmentPath, $ShortcutPath, $ExecutionPath) | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -gt 0) {
      Set-ItResult -Skipped -Because 'One or more controlled InstallMate system-effect fixtures are not cached.'
      return
    }

    $Registry = Get-InstallMateInfo -Path $RegistryPath
    $Environment = Get-InstallMateInfo -Path $EnvironmentPath
    $Shortcut = Get-InstallMateInfo -Path $ShortcutPath
    $Execution = Get-InstallMateInfo -Path $ExecutionPath

    $Registry.RegistryWrites.Count | Should -Be 1
    $Registry.RegistryWrites[0].Root | Should -Be 'HKLM'
    $Registry.RegistryWrites[0].Key | Should -Be 'Software\Your Company\Product name'
    $Registry.RegistryWrites[0].Name | Should -Be 'ResearchName'
    $Registry.RegistryWrites[0].Value | Should -Be 'ResearchData'
    $Registry.RegistryWrites[0].Complete | Should -BeTrue
    $Registry.RegistryWrites[0].IsAuthoritative | Should -BeTrue
    $Registry.RegistryWrites[0].RegistryViewPolicy | Should -Be 'ExistingKeyElseNative'
    $Environment.EnvironmentChanges.Count | Should -Be 1
    $Environment.EnvironmentChanges[0].Name | Should -Be 'RESEARCH_ENV'
    $Environment.EnvironmentChanges[0].Value | Should -Be 'ResearchValue'
    $Shortcut.Shortcuts.Count | Should -Be 1
    $Shortcut.Shortcuts[0].Title | Should -Be 'Research shortcut title'
    $Shortcut.Shortcuts[0].ResolvedTargetPath | Should -Be '%ProgramFiles%\Product name\Research.exe'
    $Shortcut.Shortcuts[0].Arguments | Should -Be '--shortcut'
    $ResearchAction = @($Execution.ExecutionActions | Where-Object Name -CEQ 'ResearchRun')
    $ResearchAction.Count | Should -Be 1
    $ResearchAction[0].ResolvedTargetPath | Should -Be '%ProgramFiles%\Product name\Research.exe'
    $ResearchAction[0].Arguments | Should -Be '--research'
    $ResearchAction[0].TimeoutMilliseconds | Should -Be 123000
  }

  It 'Should decode a controlled <ExpectedView> registry-only view' -ForEach @(
    @{ Fixture = 'RegistryView64.exe'; ExpectedView = '64-bit'; ExpectedPolicy = '64BitOnly' }
    @{ Fixture = 'RegistryView32.exe'; ExpectedView = '32-bit'; ExpectedPolicy = '32BitOnly' }
  ) {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory $Fixture
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate registry-view fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Info.RegistryWrites.Count | Should -Be 1
    $Info.RegistryWrites[0].RegistryView | Should -Be $ExpectedView
    $Info.RegistryWrites[0].RegistryViewPolicy | Should -Be $ExpectedPolicy
    $Info.RegistryWrites[0].IsAuthoritative | Should -BeTrue
  }

  It 'Should retain conditional component registry evidence without promoting it' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'RegistryConditional.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate conditional-component fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Write = $Info.RegistryWrites[0]
    $Write.Complete | Should -BeTrue
    $Write.IsConditional | Should -BeTrue
    $Write.IsAuthoritative | Should -BeFalse
    $Write.ComponentConditions[0].Condition | Should -Be '1 = 0'
    @($Info.Diagnostics.Id) | Should -Contain 'InstallMate.Registry.ComponentConditional'
  }

  It 'Should decode controlled environment install action <ExpectedAction>' -ForEach @(
    @{ Fixture = 'EnvironmentPrepend.exe'; ExpectedCode = 3; ExpectedAction = 'Prepend' }
    @{ Fixture = 'EnvironmentOverwrite.exe'; ExpectedCode = 5; ExpectedAction = 'Overwrite' }
  ) {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory $Fixture
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate environment-action fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Info.EnvironmentChanges.Count | Should -Be 1
    $Info.EnvironmentChanges[0].InstallActionCode | Should -Be $ExpectedCode
    $Info.EnvironmentChanges[0].InstallAction | Should -Be $ExpectedAction
    @($Info.Diagnostics.Id) | Should -Not -Contain 'InstallMate.Environment.ConfigurationPartiallyDecoded'
  }

  It 'Should decode the environment operation variant <Fixture>' -ForEach @(
    @{ Fixture = 'EnvironmentBase.exe'; RemoveAction = 'RemovePartialValue'; Keep = $false; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = ';' }
    @{ Fixture = 'EnvironmentUserOnly.exe'; RemoveAction = 'RemovePartialValue'; Keep = $false; User = $true; ScopeBehavior = 'CurrentUser'; Separator = ';' }
    @{ Fixture = 'EnvironmentKeepDuringUpdates.exe'; RemoveAction = 'RemovePartialValue'; Keep = $true; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = ';' }
    @{ Fixture = 'EnvironmentBothFlags.exe'; RemoveAction = 'RemovePartialValue'; Keep = $true; User = $true; ScopeBehavior = 'CurrentUser'; Separator = ';' }
    @{ Fixture = 'EnvironmentRemove0.exe'; RemoveAction = 'DoNotRemove'; Keep = $false; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = ';' }
    @{ Fixture = 'EnvironmentRemove2.exe'; RemoveAction = 'RemoveIfMatched'; Keep = $false; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = ';' }
    @{ Fixture = 'EnvironmentRemove3.exe'; RemoveAction = 'RemoveCompletely'; Keep = $false; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = ';' }
    @{ Fixture = 'EnvironmentRemove4.exe'; RemoveAction = 'RestoreOriginal'; Keep = $false; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = ';' }
    @{ Fixture = 'EnvironmentSeparatorEmpty.exe'; RemoveAction = 'RemovePartialValue'; Keep = $false; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = '' }
    @{ Fixture = 'EnvironmentSeparatorPipe.exe'; RemoveAction = 'RemovePartialValue'; Keep = $false; User = $false; ScopeBehavior = 'AllUsersWhenAvailable'; Separator = '|' }
  ) {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory $Fixture
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because "The controlled InstallMate environment fixture '$Fixture' is not cached."; return }

    $Info = Get-InstallMateInfo -Path $FixturePath
    $Environment = @($Info.EnvironmentChanges | Where-Object Name -CEQ 'RESEARCH_ENV')[0]
    $Environment.RemoveAction | Should -Be $RemoveAction
    $Environment.KeepDuringUpdates | Should -Be $Keep
    $Environment.CurrentUserOnly | Should -Be $User
    $Environment.ScopeBehavior | Should -Be $ScopeBehavior
    $Environment.Separator | Should -Be $Separator
    $Environment.ConfigurationComplete | Should -BeTrue
    @($Info.Diagnostics.Id) | Should -Not -Contain 'InstallMate.Environment.ConfigurationPartiallyDecoded'
  }

  It 'Should link current prerequisite records to their execution actions' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'PrerequisiteFlags1.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate prerequisite fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath
    $Prerequisite = @($Info.Prerequisites | Where-Object Name -CEQ 'ResearchPrerequisite')

    $Prerequisite.Count | Should -Be 1
    $Prerequisite[0].Condition | Should -Be '1'
    $Prerequisite[0].CpuSupport | Should -Be 769
    $Prerequisite[0].ExeSupport | Should -Be 769
    @($Prerequisite[0].Actions).Count | Should -Be 1
    $Prerequisite[0].Actions[0].Arguments | Should -Be '--prerequisite'
    $Prerequisite[0].Actions[0].TimeoutMilliseconds | Should -Be 123000
    $Prerequisite[0].RequiresAdministrator | Should -BeFalse
  }

  It 'Should decode the prerequisite Administrator-rights option' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'PrerequisiteFlags3.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate prerequisite-rights fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath
    $Prerequisite = @($Info.Prerequisites | Where-Object Name -CEQ 'ResearchPrerequisite')

    $Prerequisite.Count | Should -Be 1
    $Prerequisite[0].RequiresAdministrator | Should -BeTrue
    $Prerequisite[0].ObservedOptions | Should -Be @(0, 1)
    @($Info.Diagnostics.Id) | Should -Contain 'InstallMate.Prerequisite.RequiresAdministrator'
  }

  It 'Should decode and resolve a configured service record' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'ServiceLocalized.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate service fixture is not cached.'; return }
    $Info = Get-InstallMateInfo -Path $FixturePath

    $Info.Services.Count | Should -Be 1
    $Service = $Info.Services[0]
    $Service.Name | Should -Be 'ResearchService'
    $Service.DisplayName | Should -Be 'Research Service'
    $Service.Description | Should -Be 'InstallMate parser research service'
    $Service.BinaryPath | Should -Be '%ProgramFiles%\Product name\ResearchService.exe'
    $Service.Arguments | Should -Be '--service'
    $Service.LoadOrderGroup | Should -Be 'Research Group'
    $Service.Dependencies | Should -Be @('Tcpip', '+Network')
    $Service.Account | Should -Be 'LocalSystemOrUnspecified'
    $Service.ServiceTypeName | Should -Be 'OwnProcess'
    $Service.StartTypeName | Should -Be 'Manual'
    $Service.DelayedAutomaticStart | Should -BeFalse
    $Service.ErrorControlName | Should -Be 'Normal'
    $Service.ResetPeriodSeconds | Should -Be 86400
    $Service.RecoveryActionCount | Should -Be 0
    $Service.HasPassword | Should -BeFalse
    @($Info.Diagnostics.Id) | Should -Not -Contain 'InstallMate.Service.ConfigurationPartiallyDecoded'
  }

  It 'Should map a controlled service option in <Fixture>' -ForEach @(
    @{ Fixture = 'ServiceAccountType1.exe'; Property = 'Account'; Expected = 'LocalService' }
    @{ Fixture = 'ServiceAccountType2.exe'; Property = 'Account'; Expected = 'NetworkService' }
    @{ Fixture = 'ServiceKernelDriver.exe'; Property = 'ServiceTypeName'; Expected = 'KernelDriver' }
    @{ Fixture = 'ServiceFileSystemDriver.exe'; Property = 'ServiceTypeName'; Expected = 'FileSystemDriver' }
    @{ Fixture = 'ServiceType3.exe'; Property = 'ServiceTypeName'; Expected = 'OwnInteractiveProcess' }
    @{ Fixture = 'ServiceType4.exe'; Property = 'ServiceTypeName'; Expected = 'SharedProcess' }
    @{ Fixture = 'ServiceType5.exe'; Property = 'ServiceTypeName'; Expected = 'SharedInteractiveProcess' }
    @{ Fixture = 'ServiceStartMode2.exe'; Property = 'StartTypeName'; Expected = 'Automatic' }
    @{ Fixture = 'ServiceStartMode3.exe'; Property = 'DelayedAutomaticStart'; Expected = $true }
    @{ Fixture = 'ServiceStartMode5.exe'; Property = 'StartTypeName'; Expected = 'Disabled' }
    @{ Fixture = 'ServiceErrorMode0.exe'; Property = 'ErrorControlName'; Expected = 'Ignore' }
    @{ Fixture = 'ServiceErrorMode2.exe'; Property = 'ErrorControlName'; Expected = 'Severe' }
    @{ Fixture = 'ServiceErrorMode3.exe'; Property = 'ErrorControlName'; Expected = 'Critical' }
  ) {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory $Fixture
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because "The controlled InstallMate service fixture '$Fixture' is not cached."; return }

    $Service = (Get-InstallMateInfo -Path $FixturePath).Services[0]
    $Service.$Property | Should -Be $Expected
  }

  It 'Should decode service recovery actions, command, and localized reboot text' {
    $FixturePath = Join-Path $Script:InstallMateRecordFixtureDirectory 'ServiceRecoveryReboot.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The controlled InstallMate recovery-action fixture is not cached.'; return }

    $Info = Get-InstallMateInfo -Path $FixturePath
    $Service = $Info.Services[0]
    $Service.RunCommand | Should -Be '"<INSTALLDIR>\ResearchService.exe" --recover %1%'
    $Service.RebootMessage | Should -Be 'Research service restart'
    $Service.ResetPeriodSeconds | Should -Be 86400
    $Service.RecoveryActionCount | Should -Be 4
    @($Service.RecoveryActions.Action) | Should -Be @('TakeNoAction', 'RestartService', 'RestartComputer', 'RunProgram')
    @($Service.RecoveryActions.DelayMilliseconds) | Should -Be @(2000, 11000, 22000, 33000)
    @($Service.RecoveryActions.DelaySeconds) | Should -Be @(2, 11, 22, 33)
    @($Service.ObservedOptions).Count | Should -Be 0
    @($Info.Diagnostics.Id) | Should -Not -Contain 'InstallMate.Service.ConfigurationPartiallyDecoded'
  }

  It 'Should decode controlled service action <Fixture>' -ForEach @(
    @{ Fixture = 'ServiceControlInstall0.exe'; InstallCode = 0; InstallAction = 'NoAction'; RemoveCode = 0; RemoveAction = 'NoAction'; Arguments = '' }
    @{ Fixture = 'ServiceControlInstall1.exe'; InstallCode = 1; InstallAction = 'StartService'; RemoveCode = 0; RemoveAction = 'NoAction'; Arguments = '--install-start <INSTALLDIR>' }
    @{ Fixture = 'ServiceControlInstall2.exe'; InstallCode = 2; InstallAction = 'StopService'; RemoveCode = 0; RemoveAction = 'NoAction'; Arguments = '' }
    @{ Fixture = 'ServiceControlInstall3.exe'; InstallCode = 8; InstallAction = 'PauseService'; RemoveCode = 0; RemoveAction = 'NoAction'; Arguments = '' }
    @{ Fixture = 'ServiceControlInstall4.exe'; InstallCode = 4; InstallAction = 'ResumeService'; RemoveCode = 0; RemoveAction = 'NoAction'; Arguments = '' }
    @{ Fixture = 'ServiceControlInstall5.exe'; InstallCode = 32; InstallAction = 'DeleteService'; RemoveCode = 0; RemoveAction = 'NoAction'; Arguments = '' }
    @{ Fixture = 'ServiceControlRemove1.exe'; InstallCode = 0; InstallAction = 'NoAction'; RemoveCode = 1; RemoveAction = 'StartService'; Arguments = '--remove-start <INSTALLDIR>' }
    @{ Fixture = 'ServiceControlRemove2.exe'; InstallCode = 0; InstallAction = 'NoAction'; RemoveCode = 2; RemoveAction = 'StopService'; Arguments = '' }
    @{ Fixture = 'ServiceControlRemove3.exe'; InstallCode = 0; InstallAction = 'NoAction'; RemoveCode = 8; RemoveAction = 'PauseService'; Arguments = '' }
    @{ Fixture = 'ServiceControlRemove4.exe'; InstallCode = 0; InstallAction = 'NoAction'; RemoveCode = 4; RemoveAction = 'ResumeService'; Arguments = '' }
    @{ Fixture = 'ServiceControlRemove5.exe'; InstallCode = 0; InstallAction = 'NoAction'; RemoveCode = 32; RemoveAction = 'DeleteService'; Arguments = '' }
  ) {
    $FixturePath = Join-Path $Script:InstallMateServiceControlFixtureDirectory $Fixture
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because "The controlled InstallMate service-action fixture '$Fixture' is not cached."; return }

    $Info = Get-InstallMateInfo -Path $FixturePath
    $Info.ServiceActions.Count | Should -Be 1
    $Action = $Info.ServiceActions[0]
    $Action.Name | Should -Be 'Service_Action1'
    $Action.Arguments | Should -Be $Arguments
    if ($Arguments) {
      $Action.ResolvedArguments | Should -Be ($Arguments.Replace('<INSTALLDIR>', '%ProgramFiles%\Product name'))
    } else {
      $Action.ResolvedArguments | Should -BeNullOrEmpty
    }
    $Action.InstallActionCode | Should -Be $InstallCode
    $Action.InstallAction | Should -Be $InstallAction
    $Action.RemoveActionCode | Should -Be $RemoveCode
    $Action.RemoveAction | Should -Be $RemoveAction
    $Action.ConfigurationComplete | Should -BeTrue
    @($Info.Diagnostics.Id) | Should -Not -Contain 'InstallMate.ServiceAction.ConfigurationPartiallyDecoded'
  }

  It 'Should retain an unknown service action as incomplete evidence' {
    InModuleScope InstallMate {
      $Database = [byte[]]::new(96)
      [Text.Encoding]::ASCII.GetBytes("svca`0`0`0`0").CopyTo($Database, 0)
      [BitConverter]::GetBytes([uint32]5).CopyTo($Database, 0x14)
      [BitConverter]::GetBytes([uint32]([uint32]::MaxValue - 2)).CopyTo($Database, 0x18)
      $Name = [Text.Encoding]::UTF8.GetBytes('ResearchService')
      [BitConverter]::GetBytes([uint32]$Name.Length).CopyTo($Database, 0x24)
      $Name.CopyTo($Database, 0x28)
      $Cursor = 0x28 + $Name.Length
      [BitConverter]::GetBytes([uint32]0).CopyTo($Database, $Cursor)
      [BitConverter]::GetBytes([uint32]16).CopyTo($Database, $Cursor + 4)
      [BitConverter]::GetBytes([uint32]0).CopyTo($Database, $Cursor + 8)

      $Action = @(Get-InstallMateServiceControlRecord -Database $Database)[0]
      $Action.InstallActionCode | Should -Be 16
      $Action.InstallAction | Should -BeNullOrEmpty
      $Action.RemoveAction | Should -Be 'NoAction'
      $Action.ConfigurationComplete | Should -BeFalse
    }
  }

  It 'Should decode and selectively expand a legacy InstallMate package' {
    if (-not (Test-Path -LiteralPath $Script:InstallMateLegacyFixture)) { Set-ItResult -Skipped -Because 'The legacy InstallMate fixture is not cached.'; return }
    $DestinationPath = Join-Path $TestDrive 'installmate-legacy'
    $Info = Get-InstallMateInfo -Path $Script:InstallMateLegacyFixture
    $Files = @(Expand-InstallMateInstaller -Path $Script:InstallMateLegacyFixture -DestinationPath $DestinationPath -Name 'WebView2Loader.dll' -CollisionAction Rename)

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
      @($Info.Diagnostics.Message | Where-Object { $_ -like '*setup database could not be decoded*' }).Count | Should -Be 1
      { Expand-InstallMateInstaller -Path $FixturePath -CollisionAction Rename } | Should -Throw
    }
  }
}
