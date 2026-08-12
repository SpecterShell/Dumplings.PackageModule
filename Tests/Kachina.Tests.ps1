BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\Kachina'
  $Script:Akasha = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name 'AkashaNavigator.Install.1.4.0.exe' `
    -Uri 'https://github.com/ColinXHL/akasha-navigator/releases/download/v1.4.0/AkashaNavigator.Install.1.4.0.exe' `
    -Sha256 'F6A0826E59B87C80DBFAE33492A5560B3CC76A30FBC3C854478771D7CBB0629F'
  $Script:BetterGiEarly = Join-Path $Script:FixtureDirectory 'BetterGI.Install.0.40.0.exe'
  $Script:BetterGiCurrent = Join-Path $Script:FixtureDirectory 'BetterGI.Install.0.63.0.exe'
  $Script:MicaSetup = Join-Path (Split-Path $Script:FixtureDirectory -Parent) 'MicaSetup\MicaSetup-v2.5.4.exe'

  function ConvertTo-TestKachinaRecord {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][byte[]]$Content,
      [switch]$Legacy
    )

    $Stream = [IO.MemoryStream]::new()
    $Magic = $Legacy ? [byte[]](0x21, 0x49, 0x4E, 0x53) : [byte[]](0x21, 0x49, 0x4E, 0x00)
    $NameBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Name)
    $Stream.Write($Magic)
    $NameLength = [BitConverter]::GetBytes([uint16]$NameBytes.Length)
    [Array]::Reverse($NameLength)
    $Stream.Write($NameLength)
    $Stream.Write($NameBytes)
    $Length = [BitConverter]::GetBytes([uint32]$Content.Length)
    [Array]::Reverse($Length)
    $Stream.Write($Length)
    $Stream.Write($Content)
    return , $Stream.ToArray()
  }

  function ConvertTo-TestKachinaIndexEntry {
    param([string]$Name, [uint32]$Size, [uint32]$Offset)
    $Stream = [IO.MemoryStream]::new()
    $NameBytes = [Text.Encoding]::UTF8.GetBytes($Name)
    $Stream.WriteByte([byte]$NameBytes.Length)
    $Stream.Write($NameBytes)
    foreach ($Value in $Size, $Offset) {
      $Bytes = [BitConverter]::GetBytes([uint32]$Value)
      [Array]::Reverse($Bytes)
      $Stream.Write($Bytes)
    }
    return , $Stream.ToArray()
  }

  function New-TestKachinaPeBase {
    param([string]$Path, [uint16]$Machine = 0x8664)

    $Bytes = [byte[]]::new(0x2200)
    function Write-U16([int]$Offset, [uint16]$Value) { [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    function Write-U32([int]$Offset, [uint32]$Value) { [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $PeOffset = 0x100
    $OptionalOffset = $PeOffset + 24
    $SectionOffset = $OptionalOffset + 0xF0
    Write-U16 0 0x5A4D
    Write-U32 0x3C $PeOffset
    Write-U32 $PeOffset 0x00004550
    Write-U16 ($PeOffset + 4) $Machine
    Write-U16 ($PeOffset + 6) 1
    Write-U16 ($PeOffset + 20) 0xF0
    Write-U16 ($PeOffset + 22) 0x0022
    Write-U16 $OptionalOffset 0x020B
    Write-U32 ($OptionalOffset + 60) 0x200
    Write-U16 ($OptionalOffset + 68) 2
    Write-U32 ($OptionalOffset + 108) 16
    [Text.Encoding]::ASCII.GetBytes('.rdata').CopyTo($Bytes, $SectionOffset)
    Write-U32 ($SectionOffset + 8) 0x2000
    Write-U32 ($SectionOffset + 12) 0x1000
    Write-U32 ($SectionOffset + 16) 0x2000
    Write-U32 ($SectionOffset + 20) 0x200
    [Text.Encoding]::ASCII.GetBytes('!KachinaInstaller!').CopyTo($Bytes, 0x40)
    [IO.File]::WriteAllBytes($Path, $Bytes)
  }

  function Set-TestKachinaPreIndex {
    param([string]$Path, [uint32[]]$Value)
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'Read')
    try {
      $Stream.Position = 0x40 + 18
      foreach ($Item in $Value) {
        $Bytes = [BitConverter]::GetBytes([uint32]$Item)
        [Array]::Reverse($Bytes)
        $Stream.Write($Bytes)
      }
    } finally { $Stream.Dispose() }
  }

  function Add-TestKachinaBytes {
    param([string]$Path, [byte[][]]$Content)
    $Stream = [IO.File]::Open($Path, 'Append', 'Write', 'Read')
    try { foreach ($Bytes in $Content) { $Stream.Write($Bytes) } } finally { $Stream.Dispose() }
  }

  function New-TestKachinaInstaller {
    param(
      [string]$Path,
      [ValidateSet('LegacyScan', 'EarlyIndexed', 'Indexed', 'ConfigOnly')][string]$Generation,
      [ValidateSet('prefer-admin', 'prefer-user', 'force')][string]$UacStrategy = 'prefer-admin'
    )

    New-TestKachinaPeBase -Path $Path
    $Config = [ordered]@{
      source           = 'https://example.test/App.Install.${version}.exe'
      appName          = 'Kachina Test'
      publisher        = 'Test Publisher'
      regName          = 'KachinaTest'
      exeName          = 'App.exe'
      uninstallName    = 'App.uninst.exe'
      updaterName      = 'App.update.exe'
      programFilesPath = 'KachinaTest'
      title            = 'Kachina Test'
      description      = 'Fixture'
      windowTitle      = 'Kachina Test Installer'
      userDataPath     = @('${INSTALL_PATH}/User')
      uacStrategy      = $UacStrategy
    }
    $Metadata = [ordered]@{ repo_name = 'test/kachina'; tag_name = '1.2.3'; hashed = @(); patches = @(); deletes = @(); installer = [ordered]@{ size = 0; md5 = $null; xxh = $null } }
    $ConfigBytes = [Text.Encoding]::UTF8.GetBytes(($Config | ConvertTo-Json -Compress -Depth 20))
    $MetadataBytes = [Text.Encoding]::UTF8.GetBytes(($Metadata | ConvertTo-Json -Compress -Depth 20))
    if ($Generation -eq 'LegacyScan') {
      Add-TestKachinaBytes -Path $Path -Content @(
        (ConvertTo-TestKachinaRecord -Name '.config.json' -Content $ConfigBytes -Legacy),
        (ConvertTo-TestKachinaRecord -Name '.metadata.json' -Content $MetadataBytes -Legacy)
      )
      return $Path
    }
    $ConfigRecord = ConvertTo-TestKachinaRecord -Name "`0CONFIG" -Content $ConfigBytes
    if ($Generation -eq 'ConfigOnly') {
      Set-TestKachinaPreIndex -Path $Path -Value ([uint32[]](0, 0, 0, 0, 0))
      Add-TestKachinaBytes -Path $Path -Content @($ConfigRecord)
      return $Path
    }

    $MetaHeaderLength = 10 + [Text.Encoding]::UTF8.GetByteCount("`0META")
    $ConfigHeaderLength = 10 + [Text.Encoding]::UTF8.GetByteCount("`0CONFIG")
    $IndexEntryLength = (1 + [Text.Encoding]::UTF8.GetByteCount("`0CONFIG") + 8) + (1 + [Text.Encoding]::UTF8.GetByteCount("`0META") + 8)
    $IndexHeaderLength = 10 + [Text.Encoding]::UTF8.GetByteCount("`0INDEX")
    $IndexRawLength = $IndexHeaderLength + $IndexEntryLength
    if ($Generation -eq 'EarlyIndexed') {
      $ConfigDataOffset = $IndexRawLength + $ConfigHeaderLength
      $MetaDataOffset = $IndexRawLength + $ConfigRecord.Length + $MetaHeaderLength
    } else {
      $ConfigDataOffset = $ConfigHeaderLength
      $MetaDataOffset = $ConfigRecord.Length + $IndexRawLength + $MetaHeaderLength
    }
    $IndexBytes = [IO.MemoryStream]::new()
    $IndexBytes.Write((ConvertTo-TestKachinaIndexEntry -Name "`0CONFIG" -Size $ConfigBytes.Length -Offset $ConfigDataOffset))
    $IndexBytes.Write((ConvertTo-TestKachinaIndexEntry -Name "`0META" -Size $MetadataBytes.Length -Offset $MetaDataOffset))
    $IndexRecord = ConvertTo-TestKachinaRecord -Name "`0INDEX" -Content $IndexBytes.ToArray()
    $MetaRecord = ConvertTo-TestKachinaRecord -Name "`0META" -Content $MetadataBytes
    $BaseSize = 0x2200
    if ($Generation -eq 'EarlyIndexed') {
      Set-TestKachinaPreIndex -Path $Path -Value ([uint32[]]($BaseSize, $IndexRecord.Length, $ConfigRecord.Length, 0, $MetaRecord.Length))
      Add-TestKachinaBytes -Path $Path -Content @($IndexRecord, $ConfigRecord, $MetaRecord)
    } else {
      Set-TestKachinaPreIndex -Path $Path -Value ([uint32[]]($BaseSize, $ConfigRecord.Length, 0, $IndexRecord.Length, $MetaRecord.Length))
      Add-TestKachinaBytes -Path $Path -Content @($ConfigRecord, $IndexRecord, $MetaRecord)
    }
    return $Path
  }
}

Describe 'Kachina structural generations' {
  It 'detects <Generation> media from validated TLV and JSON structures' -ForEach @(
    @{ Generation = 'LegacyScan' }
    @{ Generation = 'EarlyIndexed' }
    @{ Generation = 'Indexed' }
    @{ Generation = 'ConfigOnly' }
  ) {
    $Path = Join-Path $TestDrive "$Generation.exe"
    New-TestKachinaInstaller -Path $Path -Generation $Generation
    Test-KachinaInstaller -Path $Path | Should -BeTrue
    $Info = Get-KachinaInfo -Path $Path
    $Info.FormatGeneration | Should -Be $Generation
    $Info.ProductCode | Should -Be 'KachinaTest'
    if ($Generation -eq 'ConfigOnly') {
      $Info.DisplayVersion | Should -BeNullOrEmpty
      $Info.CanExpand | Should -BeFalse
      $Info.UnresolvedFields | Should -Contain 'PayloadFiles'
      $Info.UnresolvedFields | Should -Contain 'PayloadArchitecture'
    } else {
      $Info.DisplayVersion | Should -Be '1.2.3'
    }
  }

  It 'requires valid configuration fields rather than a marker or magic alone' {
    $Path = Join-Path $TestDrive 'marker-only.exe'
    New-TestKachinaPeBase -Path $Path
    Add-TestKachinaBytes -Path $Path -Content @((ConvertTo-TestKachinaRecord -Name "`0CONFIG" -Content ([Text.Encoding]::UTF8.GetBytes('{"appName":"marker"}'))))
    Test-KachinaInstaller -Path $Path | Should -BeFalse
    if (Test-Path -LiteralPath $Script:MicaSetup) { Test-KachinaInstaller -Path $Script:MicaSetup | Should -BeFalse }
    Test-MicaSetupInstaller -Path $Script:Akasha | Should -BeFalse
  }

  It 'rejects a truncated TLV deterministically' {
    $Path = Join-Path $TestDrive 'truncated.exe'
    New-TestKachinaInstaller -Path $Path -Generation Indexed
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'Read')
    try { $Stream.SetLength($Stream.Length - 1) } finally { $Stream.Dispose() }
    Test-KachinaInstaller -Path $Path | Should -BeFalse
  }

  It 'rejects malformed configuration JSON and invalid index offsets' {
    $MalformedPath = Join-Path $TestDrive 'malformed-json.exe'
    New-TestKachinaPeBase -Path $MalformedPath
    Add-TestKachinaBytes -Path $MalformedPath -Content @((ConvertTo-TestKachinaRecord -Name "`0CONFIG" -Content ([Text.Encoding]::UTF8.GetBytes('{'))))
    Test-KachinaInstaller -Path $MalformedPath | Should -BeFalse

    $IndexPath = Join-Path $TestDrive 'invalid-index.exe'
    New-TestKachinaInstaller -Path $IndexPath -Generation Indexed
    InModuleScope Kachina -Parameters @{ Installer = $IndexPath } {
      $File = Get-Item -LiteralPath $Installer
      $Input = [IO.File]::OpenRead($Installer)
      try { $Context = Get-KachinaAnalysisContext -File $File -Stream $Input } finally { $Input.Dispose() }
      $Output = [IO.File]::Open($Installer, 'Open', 'ReadWrite', 'Read')
      try {
        $Output.Position = $Context.IndexRecord.DataOffset + $Context.IndexRecord.Length - 1
        $Output.WriteByte(0xFF)
      } finally { $Output.Dispose() }
    }
    Test-KachinaInstaller -Path $IndexPath | Should -BeFalse
  }
}

Describe 'Kachina scope and ARP projection' {
  It 'maps <Strategy> to default machine scope and expected supported scopes' -ForEach @(
    @{ Strategy = 'force'; ExpectedScopes = @('machine') }
    @{ Strategy = 'prefer-admin'; ExpectedScopes = @('machine', 'user') }
    @{ Strategy = 'prefer-user'; ExpectedScopes = @('machine', 'user') }
  ) {
    $Path = Join-Path $TestDrive "$Strategy.exe"
    New-TestKachinaInstaller -Path $Path -Generation Indexed -UacStrategy $Strategy
    $Info = Get-KachinaInfo -Path $Path
    $Info.Scope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be $ExpectedScopes
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\KachinaTest'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'KachinaTest'
    $Info.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'exe'
    $Info.InstallerSwitches.Silent | Should -Be '-S'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '-I'
    $Info.InstallerSwitches.InstallLocation | Should -Be '-D "<INSTALLPATH>"'
    $Info.RegistryRoutes.Scope | Should -Contain 'machine'
    if ($Strategy -eq 'force') { $Info.RegistryRoutes.Scope | Should -Not -Contain 'user' } else { $Info.RegistryRoutes.Scope | Should -Contain 'user' }
  }
}

Describe 'Kachina real indexed payload' {
  It 'parses Akasha metadata, payload architecture, runtimes, patches, and ARP evidence' {
    $Info = Get-KachinaInfo -Path $Script:Akasha
    $Info.FormatGeneration | Should -Be 'Indexed'
    $Info.ProductCode | Should -Be 'Akasha Navigator'
    $Info.DisplayName | Should -Be 'AkashaNavigator'
    $Info.DisplayVersion | Should -Be '1.4.0'
    $Info.Publisher | Should -Be 'ColinXHL'
    $Info.PayloadFiles.Count | Should -Be 12
    $Info.PayloadArchitectures | Should -Contain 'x64'
    $Info.ConfiguredRuntimes | Should -Contain 'Microsoft.DotNet.DesktopRuntime.8'
    $Info.ConfiguredRuntimes | Should -Contain 'Microsoft.VCRedist.2015+.x64'
    $Info.EmbeddedRuntimePackages | Should -BeNullOrEmpty
    $Info.PatchFiles.Count | Should -Be 1
    $Info.CanExpand | Should -BeTrue
    $Info.SystemEffects.CreatesUpdater | Should -BeTrue
    $Info.SystemEffects.CreatesUninstaller | Should -BeTrue
    ($Info.RegistryWrites | Where-Object Name -EQ 'EstimatedSize').Value | Should -BeGreaterThan 0
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'catalogues appended runtime installers that are omitted from the payload index' {
    $Path = Join-Path $TestDrive 'embedded-runtimes.exe'
    New-TestKachinaInstaller -Path $Path -Generation Indexed
    Add-TestKachinaBytes -Path $Path -Content @(
      (ConvertTo-TestKachinaRecord -Name 'Microsoft.DotNet.DesktopRuntime.8' -Content ([byte[]](1, 2, 3))),
      (ConvertTo-TestKachinaRecord -Name 'Microsoft.VCRedist.2015+.x64' -Content ([byte[]](4, 5, 6)))
    )

    $Info = Get-KachinaInfo -Path $Path
    $Info.EmbeddedRuntimePackages.PackageIdentifier | Should -Contain 'Microsoft.DotNet.DesktopRuntime.8'
    $Info.EmbeddedRuntimePackages.PackageIdentifier | Should -Contain 'Microsoft.VCRedist.2015+.x64'
    $Info.PayloadFiles.Path | Should -Not -Contain 'Microsoft.DotNet.DesktopRuntime.8'
  }

  It 'streams the main payload and reconstructs installed updater and uninstaller executables' {
    $Destination = Join-Path $TestDrive 'expanded'
    $Files = @(Expand-KachinaInstaller -Path $Script:Akasha -DestinationPath $Destination -Name '*.exe' -CollisionAction Rename)
    $Files.Name | Should -Contain 'AkashaNavigator.exe'
    $Files.Name | Should -Contain 'AkashaNavigator.update.exe'
    $Files.Name | Should -Contain 'AkashaNavigator.uninst.exe'
    ($Files | Where-Object Name -EQ 'AkashaNavigator.exe').Length | Should -Be 17659739
    ($Files | Where-Object Name -EQ 'AkashaNavigator.update.exe').Length | Should -Be 10098602
    $Updater = $Files | Where-Object Name -EQ 'AkashaNavigator.update.exe'
    $Stream = [IO.File]::OpenRead($Updater.FullName)
    try { $Bytes = Read-BinaryBytes -Stream $Stream -Offset 78 -Count 38 } finally { $Stream.Dispose() }
    [Text.Encoding]::ASCII.GetString($Bytes[0..17]) | Should -Be '!KachinaInstaller!'
    $Bytes[18..37] | Should -Be ([byte[]]::new(20))
  }

  It 'exports raw control records without decompressing payload content' {
    $Destination = Join-Path $TestDrive 'raw'
    $Files = @(Expand-KachinaInstaller -Path $Script:Akasha -DestinationPath $Destination -RawEntries -Name '\0CONFIG' -CollisionAction Rename)
    $Files.Count | Should -Be 1
    $Files[0].Name | Should -Be 'config.json'
    (Get-Content -LiteralPath $Files[0].FullName -Raw | ConvertFrom-Json).regName | Should -Be 'Akasha Navigator'
  }

  It 'enforces aggregate output limits and explicit collision actions' {
    { Expand-KachinaInstaller -Path $Script:Akasha -DestinationPath (Join-Path $TestDrive 'limited') -Name 'AkashaNavigator.exe' -MaximumExpandedBytes 1024 -CollisionAction Error } | Should -Throw
    $Destination = Join-Path $TestDrive 'collision'
    @(Expand-KachinaInstaller -Path $Script:Akasha -DestinationPath $Destination -Name 'AkashaNavigator.exe' -CollisionAction Error).Count | Should -Be 1
    @(Expand-KachinaInstaller -Path $Script:Akasha -DestinationPath $Destination -Name 'AkashaNavigator.exe' -CollisionAction Skip).Count | Should -Be 0
  }

  It 'rejects traversal and size/hash disagreements in internal payload projections' {
    InModuleScope Kachina -Parameters @{ Installer = $Script:Akasha; Root = $TestDrive } {
      $File = Get-Item -LiteralPath $Installer
      $Stream = [IO.File]::OpenRead($Installer)
      try {
        $Context = Get-KachinaAnalysisContext -File $File -Stream $Stream
        $Warnings = [Collections.Generic.List[string]]::new()
        $Catalog = @(Get-KachinaPayloadCatalog -Context $Context -Warnings $Warnings)
        $Main = $Catalog | Where-Object Path -EQ 'AkashaNavigator.exe' | Select-Object -First 1
        $Traversal = $Main.PSObject.Copy()
        $Traversal.Path = '..\escape.exe'
        { Export-KachinaPayloadSelection -Context $Context -Catalog @($Traversal) -DestinationPath (Join-Path $Root 'traversal') -CollisionAction Error } | Should -Throw
        $WrongSize = $Main.PSObject.Copy()
        $WrongSize.ExpectedSize = [long]$WrongSize.ExpectedSize - 1
        { Export-KachinaPayloadItem -Context $Context -Item $WrongSize -DestinationPath (Join-Path $Root 'wrong-size.exe') -MaximumBytes 268435456 } | Should -Throw
        $WrongMd5 = $Main.PSObject.Copy()
        $WrongMd5.HashAlgorithm = 'MD5'
        $WrongMd5.Hash = '00000000000000000000000000000000'
        { Export-KachinaPayloadItem -Context $Context -Item $WrongMd5 -DestinationPath (Join-Path $Root 'wrong-md5.exe') -MaximumBytes 268435456 } | Should -Throw
      } finally { $Stream.Dispose() }
    }
  }
}

Describe 'Kachina analyzer integration' {
  It 'routes Kachina before MicaSetup and generic Tauri fallbacks' {
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:Akasha
    $Candidate = $Analysis.DetectedFamilies | Where-Object Family -EQ 'Kachina' | Select-Object -First 1
    $Result = $Analysis.ParserResults | Where-Object Name -EQ 'Kachina' | Select-Object -First 1
    $Candidate.ValidationStatus | Should -Be 'ConfirmedParser'
    $Candidate.IsOuterContainer | Should -BeTrue
    $Analysis.DetectedFamilies.Family | Should -Not -Contain 'MicaSetup'
    $Result.Success | Should -BeTrue
    $Result.Result.ProductCode | Should -Be 'Akasha Navigator'
    $Result.Result.SuggestedManifestFields.InstallerType | Should -Be 'exe # Kachina'
    $Result.Result.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '-S'
  }

  It 'provides complete conservative authoring suggestions' {
    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/AkashaNavigator.Install.1.4.0.exe' -InstallerPath $Script:Akasha -Architecture x64
    $Suggestion.BlockingIssues | Should -BeNullOrEmpty
    $Suggestion.Installers[0].ProductCode | Should -Be 'Akasha Navigator'
    $Suggestion.Installers[0].Scope | Should -Be 'machine'
    $Suggestion.Suggestions.FamilyDefaults.InstallerType | Should -Be 'exe # Kachina'
  }

  It 'updates existing generic EXE identity fields through manifest processing' {
    $Url = 'https://example.test/AkashaNavigator.Install.1.4.0.exe'
    $Installer = [ordered]@{
      Architecture           = 'x64'
      InstallerType          = 'exe'
      InstallerUrl           = $Url
      ProductCode            = 'Old.Akasha'
      AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Old Akasha'; DisplayVersion = '0.0.0'; Publisher = 'Old Publisher' })
    }
    $Result = InModuleScope WinGetManifestUpdate -Parameters @{ Entry = $Installer; Url = $Url; InstallerPath = $Script:Akasha } {
      $Logger = { param($Message, $Level) }
      Update-WinGetInstallerManifestInstallerMetadata -Installer $Entry -OldInstaller ($Entry | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{ $Url = $InstallerPath }) -Logger $Logger
    }

    $Result.ProductCode | Should -Be 'Akasha Navigator'
    $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'AkashaNavigator'
    $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '1.4.0'
    $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'ColinXHL'
  }

  It 'parses the same installer concurrently in independent runspaces' {
    $ModulePath = (Resolve-Path (Join-Path $PSScriptRoot '..\PackageModule.psd1')).Path
    $InstallerPath = $Script:Akasha
    $Results = 1..2 | ForEach-Object -Parallel {
      Import-Module $using:ModulePath -Force
      (Get-KachinaInfo -Path $using:InstallerPath).ProductCode
    } -ThrottleLimit 2
    $Results | Should -Be @('Akasha Navigator', 'Akasha Navigator')
  }
}

Describe 'Kachina historical real layouts' {
  It 'parses the cached BetterGI 0.40 production indexed media' {
    if (-not (Test-Path -LiteralPath $Script:BetterGiEarly)) { Set-ItResult -Skipped -Because 'The optional BetterGI 0.40 fixture is not cached.'; return }
    (Get-DumplingsTestFixtureHash -Path $Script:BetterGiEarly) | Should -Be 'C4683C080827F7A1C70CD2BFA2177B976FF4C5FAF07A2D6F732A5045B8882203'
    $Info = Get-KachinaInfo -Path $Script:BetterGiEarly
    $Info.FormatGeneration | Should -Be 'Indexed'
    $Info.ProductCode | Should -Be 'BetterGI'
  }

  It 'reports downloadable runtime requirements in cached BetterGI 0.63 media' {
    if (-not (Test-Path -LiteralPath $Script:BetterGiCurrent)) { Set-ItResult -Skipped -Because 'The optional BetterGI 0.63 fixture is not cached.'; return }
    (Get-DumplingsTestFixtureHash -Path $Script:BetterGiCurrent) | Should -Be '777EB7605A6E4491EDCA1D327A32770D4A1FDCD102E699F842D320AA29A938B9'
    $Info = Get-KachinaInfo -Path $Script:BetterGiCurrent
    $Info.FormatGeneration | Should -Be 'Indexed'
    $Info.ProductCode | Should -Be 'BetterGI'
    $Info.RuntimePackages.PackageIdentifier | Should -Contain 'Microsoft.DotNet.DesktopRuntime.8'
    $Info.RuntimePackages.PackageIdentifier | Should -Contain 'Microsoft.VCRedist.2015+.x64'
    $Info.RuntimePackages.IsEmbedded | Should -Not -Contain $true

    $Destination = Join-Path $TestDrive 'deduplicated'
    $Files = @(Expand-KachinaInstaller -Path $Script:BetterGiCurrent -DestinationPath $Destination -Name '*original_resin_top_icon.png' -CollisionAction Error)
    $Files.Count | Should -Be 2
    ($Files | Get-FileHash -Algorithm SHA256).Hash | Select-Object -Unique | Should -HaveCount 1
  }
}
