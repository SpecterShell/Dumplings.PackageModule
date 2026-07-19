BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallAware.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PaquetBuilder.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'QSetup.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'DeployMaster.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'CreateInstall.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallMate.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\AdditionalGenericExeParsers'
  $Script:DeployMasterFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\DeployMaster\Generated'
  $Script:DeployMasterLegacyFixture = Join-Path (Split-Path -Parent $Script:DeployMasterFixtureDirectory) 'Setup Brinno Video Player.exe'
  $Script:InstallMateFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallMate\Generated'
  $Script:InstallMateLegacyFixture = Join-Path (Split-Path -Parent $Script:InstallMateFixtureDirectory) 'PoP8Setup.exe'

  function ConvertTo-TestQSetupRecord {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Content, [switch]$Required)
    $RequiredMarker = if ($Required) { '*' } else { '' }
    $Header = [Text.Encoding]::ASCII.GetBytes("|$Name$RequiredMarker|123456|")
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try { $Encoder.Write($Header, 0, $Header.Length); $Encoder.Write($Content, 0, $Content.Length) } finally { $Encoder.Dispose() }
    return [BitConverter]::GetBytes([uint32]$Compressed.Length) + $Compressed.ToArray()
  }

  function New-TestCreateInstallFixture {
    param(
      [Parameter(Mandatory)][string]$Path,
      [ValidateRange(0, 1048576)][int]$PrefixLength = 512
    )

    $Content = [Text.Encoding]::UTF8.GetBytes('static CreateInstall payload')
    $MetadataStream = [IO.MemoryStream]::new()
    $MetadataWriter = [IO.BinaryWriter]::new($MetadataStream, [Text.Encoding]::UTF8, $true)
    try {
      $MetadataWriter.Write([uint16]0)
      $MetadataWriter.Write([long]0)
      $MetadataWriter.Write([uint64]$Content.Length)
      $MetadataWriter.Write([uint64](9 + $Content.Length))
      $MetadataWriter.Write([uint32]0)
      $MetadataWriter.Write([Text.Encoding]::UTF8.GetBytes('payload.txt'))
      $MetadataWriter.Write([byte]0)
    } finally { $MetadataWriter.Dispose() }
    $Metadata = $MetadataStream.ToArray()
    $HeaderSize = 74 + $Metadata.Length
    $SummarySize = 9 + $Content.Length
    $ArchiveFileSize = $PrefixLength + $HeaderSize + $SummarySize

    $Output = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Output, [Text.Encoding]::UTF8, $true)
    try {
      $Writer.Write([byte[]]::new($PrefixLength))
      $Writer.Write([Text.Encoding]::ASCII.GetBytes("GEA`0"))
      $Writer.Write([uint16]0)
      $Writer.Write([uint32]0x12345678)
      $Writer.Write([byte]2)
      $Writer.Write([byte]0)
      $Writer.Write([long]0)
      $Writer.Write([uint32]0)
      $Writer.Write([uint16]1)
      $Writer.Write([uint32]$HeaderSize)
      $Writer.Write([long]$SummarySize)
      $Writer.Write([uint32]$Metadata.Length)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([uint32]0)
      $Writer.Write([byte]8)
      $Writer.Write([byte]1)
      $Writer.Write([byte]1)
      $Writer.Write([byte]0)
      $Writer.Write($Metadata)
      $Writer.Write([byte]0x80)
      $Writer.Write([uint64]$Content.Length)
      $Writer.Write($Content)
    } finally { $Writer.Dispose() }
    [IO.File]::WriteAllBytes($Path, $Output.ToArray())
  }
}

Describe 'InstallAware static parser' {
  It 'Should require InstallAware project evidence in a validated embedded 7z' {
    $ArchiveBytes = [Convert]::FromBase64String('N3q8ryccAASC6rZeGQAAAAAAAABqAAAAAAAAAIO0oUEBABTvu79NWiBzeW50aGV0aWMgc2V0dXAAAQQGAAEJGQAHCwEAASEhAQAMFQAICgEliOZUAAAFARkMAAAAAAAAAAAAAAAAESUARQB4AGEAbQBwAGwAZQBfAFMAZQB0AHUAcAAuAGUAeABlAAAAFAoBALa5/FNLEN0BFQYBACAAAAAAAA==')
    $FixturePath = Join-Path $Script:FixtureDirectory 'installaware-archive.bin'
    [IO.File]::WriteAllBytes($FixturePath, ([byte[]]::new(1024) + $ArchiveBytes))

    InModuleScope InstallAware -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $ArchiveData = Get-InstallAwareArchiveData -Path $FixturePath
      $ArchiveData.Range.Offset | Should -Be 1024
      $ArchiveData.Entries.FullName | Should -Contain 'Example_Setup.exe'
      $ArchiveData.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
    }
  }
}

Describe 'Paquet Builder static parser' {
  It 'Should classify independent payload and runtime archives' {
    $PayloadBytes = [Convert]::FromBase64String('N3q8ryccAAQ9qmANEQAAAAAAAABaAAAAAAAAAMFZj+oBAAzvu79NWiBwYXlsb2FkAAEEBgABCREABwsBAAEhIQEADA0ACAoBlIuc5QAABQEZDAAAAAAAAAAAAAAAABERAGEAcABwAC4AZQB4AGUAAAAZAgAAFAoBAB62AVRLEN0BFQYBACAAAAAAAA==')
    $RuntimeBytes = [Convert]::FromBase64String('N3q8ryccAARvFqxziQAAAAAAAAAhAAAAAAAAAIeEEHoBABHvu79NWiBjb3Jl77u/cHJvcHMAAACBMweuD89dLwwHyEN/QbH6/eXHfeltPRF+KAQ4jdN8i3B2bHASkmtshsURP/CTxIVxKBlS3RJpSTQfS1uagxDwitrxEOECC63BwAFZFPCO/UlgqXK0gK4zcbXJH8lrfwIF5lsbjlRuLVrCC1IqcmXAABcGFgEJcwAHCwEAASMDAQEFXQAQAAAMgIYKASqU5xkAAA==')
    $FixturePath = Join-Path $Script:FixtureDirectory 'paquet-archives.bin'
    [IO.File]::WriteAllBytes($FixturePath, ([byte[]]::new(2048) + $PayloadBytes + [byte[]]::new(73) + $RuntimeBytes))

    InModuleScope PaquetBuilder -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $ArchiveData = Get-PaquetBuilderArchiveData -Path $FixturePath
      $ArchiveData.Payload.Entries.FullName | Should -Be @('app.exe')
      $ArchiveData.Runtime.Entries.FullName | Should -Contain 'pbfprop.dat'
      $ArchiveData.Runtime.Entries.FullName | Should -Contain 'PBCore64.dll'
      $ArchiveData.Payload.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
      $ArchiveData.Runtime.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
    }
  }
}

Describe 'QSetup static parser' {
  It 'Should parse explicit Setup.txt ARP, scope, architecture, and association directives' {
    $SetupText = @'
SET_PROG_NAME(Example QSetup Product);
SET_PROJECT_NAME(ExampleProject);
SET_PROG_VERSION(4.5.6);
SET_COMPANY_NAME(Example Publisher);
SET_COMPOSER_BUILD(12.0.0.5);
SET_TARGET_DIR(<ProgramFiles>\Example);
SET_PROG_EXE_NAME(<Application Folder>\Example.exe);
SET_CREATE_UNINSTALL;
SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS;
SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME(Example QSetup ARP);
SET_ALL_USERS;
SET_ALLOWED_OS(10.64,11.64);
SET_ADD_ASSOCIATION_ITEM(|Example.Document|Example document|.example|Example|<Application Folder>\Example.exe|<Application Folder>\Example.exe|0|Create|Remove||);
'@
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath

      $Info.DisplayName | Should -Be 'Example QSetup ARP'
      $Info.DisplayVersion | Should -Be '4.5.6'
      $Info.Publisher | Should -Be 'Example Publisher'
      $Info.ProductCode | Should -Be 'Example QSetup ARP'
      $Info.Scope | Should -Be 'machine'
      $Info.SupportedArchitectures | Should -Be @('x64')
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.FileExtensions | Should -Be @('example')
      $Info.Records.Name | Should -Be @('Engine.exe', 'Setup.txt')
    }
  }
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

Describe 'CreateInstall static parser' {
  It 'Should parse and expand a bounded GEA v2 stored file' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-createinstall.exe'
    $DestinationPath = Join-Path $Script:FixtureDirectory 'createinstall-expanded'
    New-TestCreateInstallFixture -Path $FixturePath
    Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction SilentlyContinue

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath; DestinationPath = $DestinationPath } {
      param($FixturePath, $DestinationPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'requireAdministrator' }
      $Info = Get-CreateInstallInfo -Path $FixturePath
      $Files = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath)

      $Info.GEA.MajorVersion | Should -Be 2
      $Info.GEA.EntryCount | Should -Be 1
      $Info.GEA.CompressionMethods | Should -Be @('Store')
      $Info.Scope | Should -Be 'machine'
      $Info.CanExpand | Should -BeTrue
      $Files.Name | Should -Be @('payload.txt')
      Get-Content -LiteralPath $Files[0].FullName -Raw | Should -Be 'static CreateInstall payload'
    }
  }

  It 'Should decode a source-backed LZGE order-six regression vector' {
    InModuleScope CreateInstall {
      Import-CreateInstallLzgeDecoder
      # Compressed dlgsets.res block from the external real-installer fixture.
      $Compressed = [Convert]::FromBase64String('SbGuB7oAAABax+/4Rks3R5B1UJUlTtymSUq5CSdFqE7FOjuEfVOqp4HoAdnk1Qzu66kVbwObkpO+52PRlK48jwueFvTzw7nh4btvQ8O6vJ/dHs06vBt13o1vDvvQCzWiROqTeN0Ij3bS6qwwSAQDJYwjAMQvzFaPjeW6fvatqXmx+he4pKKr5aRt0cbRGrvU7MYyzQMogmcs4PQqsFyi1IVV/L1Wxnf/L2i4Ql/L32asbki9hI49IzZkk8TmmbobK6Jtl4WJDX03EypK69jr54v9ArD7XjZ3TfHQpnmaZjG9W9Oo52VMXW+L0eoni7q/3fz1KttSBRXm5LdFfeTkKSql8ESTfmbvi0U1jDMiof4F9dwsqVzn2Rpex+P4Zb/x/ZCYpvcXhA==')
      $Decoded = [Dumplings.Gentee.LzgeDecoder]::Decode($Compressed, 588)

      $Decoded.Length | Should -Be 588
      [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Decoded)) |
        Should -Be 'F28B2E9BAF05FFC72B3059C354EA35A10AA65AE3A574B7110885545699B265CD'
    }
  }

  It 'Should parse a standalone GEA image such as the SETUP_TEMP resource' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-createinstall-standalone.gea'
    New-TestCreateInstallFixture -Path $FixturePath -PrefixLength 0

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      $Layout = Get-CreateInstallArchiveLayout -Path $FixturePath

      $Layout.ArchiveOffset | Should -Be 0
      $Layout.Entries.FullName | Should -Be @('payload.txt')
    }
  }

  It 'Should derive Balabolka ARP identity from its compiled addremoveext call' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'CrossPlusA.Balabolka.setup.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'Balabolka'
    $Info.ProductCodeEvidence | Should -Be 'Compiled Gentee addremoveext uninstall-key argument'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.UninstallKeyName | Should -Be @('Balabolka')
    $Info.GEA.UnsupportedCompressionMethods | Should -Contain 'PPMd'
    $Info.CanExpand | Should -BeFalse
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should derive the builder ARP identity without package-specific rules' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'Novostrim.CreateInstall.8.11.2.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official CreateInstall builder fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'CreateInstall'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.Count | Should -Be 1
    $Info.Warnings | Should -BeNullOrEmpty
  }
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
