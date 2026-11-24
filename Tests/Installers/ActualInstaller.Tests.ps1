. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global
  Import-CabinetDependency

  $Script:WaybackRoot = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\ActualInstaller\Wayback'
  $Script:Actual38 = Join-Path $Script:WaybackRoot '20101206035812-aisetup.exe'
  $Script:Actual48 = Join-Path $Script:WaybackRoot '20130515130805-aisetup.exe'
  $Script:Actual52 = Join-Path $Script:WaybackRoot '20131116064642-aisetup.exe'
  $Script:Actual66 = Join-Path $Script:WaybackRoot '20170312085219-aisetup.exe'
  $Script:Actual67 = Join-Path $Script:WaybackRoot '20170808205410-aisetup.exe'
  $Script:Actual80 = Join-Path $Script:WaybackRoot '20200715220806-aisetup.exe'
  $Script:Actual82 = Join-Path $Script:WaybackRoot '20210227072937-aisetup.exe'
  $Script:Actual82Truncated = Join-Path $Script:WaybackRoot '20210603164500-aisetup.exe'
  $Script:Actual83 = Join-Path $Script:WaybackRoot '20210908003141-aisetup.exe'
  $Script:Actual84 = Join-Path $Script:WaybackRoot '20211026215016-aisetup.exe'
  $Script:Actual96Fixed = Join-Path $Script:WaybackRoot '20231205134440-aisetup9.6.exe'
  $Script:ActualUpdater481 = Join-Path $Script:WaybackRoot '20221213231049-ausetup.exe'
  $Script:ActualDownloader = Join-Path $Script:WaybackRoot '20231205103125-Downloader.exe'
  $Script:Actual10 = Join-Path $Script:WaybackRoot '20250130150752-ActualInstallerFree10-online.exe'
  $Script:ActualUpdater50 = Join-Path $Script:WaybackRoot 'Current-ActualUpdaterFree5.0.exe'
  $Script:Builder96Root = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\ActualInstaller\9.6'
  $Script:Builder98Root = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\ActualInstaller\9.8'

  function New-TestZipFile {
    param ([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][Collections.IDictionary]$Entry)

    $Archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($Name in $Entry.Keys) {
        $ZipEntry = $Archive.CreateEntry([string]$Name)
        $Writer = [IO.StreamWriter]::new($ZipEntry.Open(), [Text.UTF8Encoding]::new($false))
        try { $Writer.Write([string]$Entry[$Name]) } finally { $Writer.Dispose() }
      }
    } finally {
      $Archive.Dispose()
    }
  }

  function Add-TestFileBytes {
    param ([Parameter(Mandatory)][string]$DestinationPath, [Parameter(Mandatory)][string[]]$SourcePath)

    $Destination = [IO.File]::Open($DestinationPath, 'Append', 'Write', 'None')
    try {
      foreach ($SourceFile in $SourcePath) {
        $Source = [IO.File]::OpenRead($SourceFile)
        try { $Source.CopyTo($Destination) } finally { $Source.Dispose() }
      }
    } finally {
      $Destination.Dispose()
    }
  }

  function New-TestActualInstallerZipFixture {
    param (
      [Parameter(Mandatory)][string]$Path,
      [string]$AdditionalSetup,
      [string]$AdditionalRegistry,
      [string]$AdditionalCommands,
      [switch]$DuplicatePayloadIndex
    )

    $Stem = [IO.Path]::GetFileNameWithoutExtension($Path)
    $PayloadZip = Join-Path $TestDrive "$Stem-payload.zip"
    $MetadataZip = Join-Path $TestDrive "$Stem-metadata.zip"
    New-TestZipFile -Path $PayloadZip -Entry ([ordered]@{ '0' = 'payload' })
    if ($DuplicatePayloadIndex) {
      $Archive = [IO.Compression.ZipFile]::Open($PayloadZip, [IO.Compression.ZipArchiveMode]::Update)
      try {
        $Duplicate = $Archive.CreateEntry('0')
        $Writer = [IO.StreamWriter]::new($Duplicate.Open(), [Text.UTF8Encoding]::new($false))
        try { $Writer.Write('duplicate') } finally { $Writer.Dispose() }
      } finally { $Archive.Dispose() }
    }
    $Configuration = @"
[Setup]
AIVer=9.8
AppName=Example Actual
AppVersion=<V>
CompanyName=Example Vendor
GUID={33333333-3333-3333-3333-333333333333}
InstallLevel=3
RunAsAdmin=0
x64=0
InstallDir=<AppData>\<AppName>
AltInstallDir=<ProgramFiles>\<AppName>
MainExe=<InstallDir>\bin\Example.exe
Uninstall=1
ShowAddRemove=1
UninstallFile=Uninstall.exe
$AdditionalSetup
[Files]
0=<InstallDir>\bin\Example.exe*?1*?Overwrite*?Yes
[Registry]
0=HKEY_CURRENT_USER\Software\Classes\actualtest*?URL Protocol*?REG_SZ*?*?Yes*?No*?Default
1=HKEY_CURRENT_USER\Software\Classes\actualtest\shell\open\command*?*?REG_SZ*?"<MainExecutable>" "%1"*?Yes*?No*?Default
$AdditionalRegistry
[Extensions]
0=aip*?<MainExecutable>*?Actual Installer Project*?*?*?*?<MainExecutable>*?1
[Commands]
$AdditionalCommands
"@
    New-TestZipFile -Path $MetadataZip -Entry ([ordered]@{ 'aisetup.ini' = $Configuration; 'Englishai.lng' = 'language' })
    [IO.File]::Copy((Join-Path $PSHOME 'pwsh.exe'), $Path, $true)
    Add-TestFileBytes -DestinationPath $Path -SourcePath @($PayloadZip, $MetadataZip)
    return $Path
  }

  function New-TestActualInstallerCabinetFixture {
    param (
      [Parameter(Mandatory)][string]$Path,
      [long]$DeclaredLengthAdjustment = 0
    )

    $PayloadSource = Join-Path $TestDrive 'cab-payload-source'
    $MetadataSource = Join-Path $TestDrive 'cab-metadata-source'
    $null = New-Item -Path $PayloadSource, $MetadataSource -ItemType Directory -Force
    [IO.File]::WriteAllText((Join-Path $PayloadSource 'Payload.txt'), 'cabinet payload')
    $PayloadCab = Join-Path $TestDrive 'actual-payload.cab'
    [Microsoft.Deployment.Compression.Cab.CabInfo]::new($PayloadCab).Pack($PayloadSource)
    $PayloadCabLength = (Get-Item -LiteralPath $PayloadCab).Length
    $DeclaredPayloadCabLength = $PayloadCabLength + $DeclaredLengthAdjustment
    $Configuration = @"
[Setup]
Version=4.8
AppName=Cabinet Actual
AppVersion=4.8
CompanyName=Example Vendor
Admin=1
InstallationPath=<ProgramFiles>\<AppName>
MainExecutable=<InstallDir>\Payload.txt
Uninstall=1
ShowAddRemove=1
[Files]
0=<InstallDir>\Payload.txt?${DeclaredPayloadCabLength}?Overwrite?Yes
"@
    [IO.File]::WriteAllText((Join-Path $MetadataSource 'aisetup.ini'), $Configuration, [Text.UTF8Encoding]::new($false))
    $MetadataCab = Join-Path $TestDrive 'actual-metadata.cab'
    [Microsoft.Deployment.Compression.Cab.CabInfo]::new($MetadataCab).Pack($MetadataSource)
    [IO.File]::Copy((Join-Path $PSHOME 'pwsh.exe'), $Path, $true)
    Add-TestFileBytes -DestinationPath $Path -SourcePath @($MetadataCab, $PayloadCab)
    return $Path
  }

  function New-TestActualInstallerExternalDataFixture {
    param (
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)][string]$CompanionPath
    )

    $Configuration = @'
[Setup]
AIVer=9.8
AppName=External Actual
AppVersion=1.0
CompanyName=Example Vendor
InstallLevel=3
RunAsAdmin=0
x64=0
InstallDir=<AppData>\<AppName>
Uninstall=0
ShowAddRemove=0
DataFileName=payload.7z
'@
    $MetadataZip = Join-Path $TestDrive 'actual-external-metadata.zip'
    New-TestZipFile -Path $MetadataZip -Entry ([ordered]@{ 'aisetup.ini' = $Configuration; 'Englishai.lng' = 'language' })
    [IO.File]::Copy((Join-Path $PSHOME 'pwsh.exe'), $Path, $true)
    Add-TestFileBytes -DestinationPath $Path -SourcePath @($MetadataZip)

    # Tiny deterministic 7z/LZMA archive containing payload.txt =
    # "external payload". The fixture is decoded in-process; tests never invoke
    # an external archiver or extractor.
    $ArchiveBytes = [Convert]::FromBase64String('N3q8ryccAASoH5CZFAAAAAAAAABiAAAAAAAAAMY4JIMBAA9leHRlcm5hbCBwYXlsb2FkAAEEBgABCRQABwsBAAEhIQEADBAACAoBajD+7gAABQEZDAAAAAAAAAAAAAAAABEZAHAAYQB5AGwAbwBhAGQALgB0AHgAdAAAABkCAAAUCgEAvb9jjo0+3QEVBgEAIAAAAAAA')
    [IO.File]::WriteAllBytes($CompanionPath, $ArchiveBytes)
    return $Path
  }
}

Describe 'Actual Installer static parser' {
  It 'parses indexed ZIP media, scope alternatives, registry evidence, and placeholders' {
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-zip.exe')
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.Path | Should -Be ([IO.Path]::GetFullPath($Fixture))
    $Info.FormatGeneration | Should -Be 'Zip6Plus'
    $Info.ProductCode | Should -Be '{33333333-3333-3333-3333-333333333333}'
    $Info.DisplayName | Should -Be 'Example Actual'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.Publisher | Should -Be 'Example Vendor'
    $Info.Scope | Should -BeNullOrEmpty
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.DefaultScope | Should -Be 'user'
    $Info.DefaultInstallLocation | Should -Be '%APPDATA%\Example Actual'
    $Info.Protocols | Should -Be 'actualtest'
    $Info.FileExtensions | Should -Be 'aip'
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Metadata.DynamicVersion'
    $Info.InstallerSwitches.Silent | Should -Be '/S'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/S'
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.Operations.Files[0].IfExistsMode | Should -Be 'Overwrite'
    $Info.Operations.Files[0].RemoveOnUninstall | Should -BeTrue
    $Info.Operations.Files[0].PolicyEncoding | Should -Be 'LegacyFields'
    $Info.FileExtensionAssociations[0].Format | Should -Be 'Modern8'
    $Info.FileExtensionAssociations[0].Executable | Should -Be '%APPDATA%\Example Actual\bin\Example.exe'
  }

  It 'extracts mapped installed paths and exact raw containers' {
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-extract.exe')
    $Output = Join-Path $TestDrive 'actual-output'
    $Files = @(Expand-ActualInstallerInstaller -Path $Fixture -DestinationPath $Output -CollisionAction Rename)

    $Files | Should -HaveCount 1
    $Files[0].FullName | Should -Be (Join-Path $Output 'bin\Example.exe')
    [IO.File]::ReadAllText($Files[0].FullName) | Should -Be 'payload'

    $Raw = @(Expand-ActualInstallerInstaller -Path $Fixture -DestinationPath (Join-Path $TestDrive 'actual-raw') -RawEntries -CollisionAction Rename)
    $Raw | Should -HaveCount 2
    $Raw.Name | Should -Contain 'container-0000.zip'
    $Raw.Name | Should -Contain 'container-0001.zip'
  }

  It 'exports metadata entries separately from installed payloads' {
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-metadata.exe')
    $Output = Join-Path $TestDrive 'actual-metadata-output'
    $Files = @(Expand-ActualInstallerInstaller -Path $Fixture -DestinationPath $Output -MetadataEntries -Name '*Englishai.lng' -CollisionAction Error)

    $Files | Should -HaveCount 1
    $Files[0].FullName | Should -Be (Join-Path $Output '_actual\metadata\Englishai.lng')
    [IO.File]::ReadAllText($Files[0].FullName) | Should -Be 'language'
  }

  It 'parses metadata-only Setup EXE plus Data media and extracts a supplied 7z companion' {
    $Companion = Join-Path $TestDrive 'payload.7z'
    $Fixture = New-TestActualInstallerExternalDataFixture -Path (Join-Path $TestDrive 'actual-external.exe') -CompanionPath $Companion
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.FormatGeneration | Should -Be 'ZipExternalData'
    $Info.MediaInfo.CompanionDataFile | Should -Be 'payload.7z'
    $Info.MediaInfo.CompanionArchiveFormat | Should -Be '7z/LZMA'
    $Info.PayloadCatalog | Should -BeNullOrEmpty
    $CompleteInfo = Get-ActualInstallerInfo -Path $Fixture -CompanionFile $Companion
    $CompleteInfo.CompanionPayloadCatalog | Should -HaveCount 1
    $CompleteInfo.InstalledPayloadCatalog | Should -HaveCount 1
    $CompleteInfo.Diagnostics.Id | Should -Contain 'ActualInstaller.Extraction.CompanionDataAnalyzed'
    $CompleteInfo.Diagnostics.Id | Should -Not -Contain 'ActualInstaller.Extraction.CompanionDataRequired'
    { Expand-ActualInstallerInstaller -Path $Fixture -DestinationPath (Join-Path $TestDrive 'external-missing') -CollisionAction Error } | Should -Throw '*requires companion data file*'
    $WrongName = Join-Path $TestDrive 'wrong-name.7z'
    [IO.File]::Copy($Companion, $WrongName)
    { Expand-ActualInstallerInstaller -Path $Fixture -CompanionFile $WrongName -DestinationPath (Join-Path $TestDrive 'external-wrong') -CollisionAction Error } | Should -Throw '*does not match compiled DataFileName*'
    { Expand-ActualInstallerInstaller -Path $Fixture -CompanionFile $Companion -DestinationPath (Join-Path $TestDrive 'external-limited') -MaximumExpandedBytes 8 -CollisionAction Error } | Should -Throw '*output limit*'

    $Output = Join-Path $TestDrive 'external-output'
    $Files = @(Expand-ActualInstallerInstaller -Path $Fixture -CompanionFile $Companion -DestinationPath $Output -CollisionAction Error)
    $Files | Should -HaveCount 1
    $Files[0].FullName | Should -Be (Join-Path $Output 'payload.txt')
    [IO.File]::ReadAllText($Files[0].FullName) | Should -Be 'external payload'
  }

  It 'projects complete literal custom uninstall registry entries' {
    $AdditionalSetup = "Uninstall=0`r`nShowAddRemove=0"
    $AdditionalRegistry = @'
2=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Actual*?DisplayName*?REG_SZ*?<AppName>*?Yes*?Yes*?Default
3=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Actual*?DisplayVersion*?REG_SZ*?1.2.3*?Yes*?Yes*?Default
4=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Actual*?Publisher*?REG_SZ*?<CompanyName>*?Yes*?Yes*?Default
5=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Actual*?InstallLocation*?REG_SZ*?<InstallDir>*?Yes*?Yes*?Default
6=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Actual*?UninstallString*?REG_SZ*?"<InstallDir>\Remove.exe"*?Yes*?Yes*?Default
7=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Actual*?QuietUninstallString*?REG_SZ*?"<InstallDir>\Remove.exe" /S*?Yes*?Yes*?Default
'@
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-custom-arp.exe') -AdditionalSetup $AdditionalSetup -AdditionalRegistry $AdditionalRegistry
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.ProductCode | Should -Be 'Custom.Actual'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries | Should -HaveCount 1
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Example Actual'
    $Info.AppsAndFeaturesEntries[0].Publisher | Should -Be 'Example Vendor'
    $Info.DefaultInstallLocation | Should -Be '%APPDATA%\Example Actual'
    $Info.UninstallString | Should -Be '"%APPDATA%\Example Actual\Remove.exe"'
    $Info.QuietUninstallString | Should -Be '"%APPDATA%\Example Actual\Remove.exe" /S'
    $Info.UninstallerCommandEvidence.Source | Should -Be 'CustomRegistry'
    $Info.UninstallerCommandEvidence.SilentCommand | Should -Be '"%APPDATA%\Example Actual\Remove.exe" /S'
    $Info.RegistryWrites[0].RegistryView | Should -Be '32-bit'
    $Info.RegistryWrites[0].OverwriteIfExists | Should -BeTrue
  }

  It 'uses a custom uninstall key as the ARP hive and view when built-in registration is disabled' {
    $AdditionalSetup = "Uninstall=0`r`nShowAddRemove=0"
    $AdditionalRegistry = '2=HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Machine.Actual*?DisplayName*?REG_SZ*?<AppName>*?Yes*?Yes*?64-bit'
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-custom-machine-arp.exe') -AdditionalSetup $AdditionalSetup -AdditionalRegistry $AdditionalRegistry
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.Scope | Should -BeNullOrEmpty
    $Info.ProductCode | Should -Be 'Custom.Machine.Actual'
    $Info.RegistryHive | Should -Be 'HKLM'
    $Info.RegistryView | Should -Be '64-bit'
  }

  It 'does not expose hidden custom uninstall keys as visible ARP evidence' {
    $AdditionalSetup = "Uninstall=0`r`nShowAddRemove=0"
    $AdditionalRegistry = @'
2=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Actual*?DisplayName*?REG_SZ*?<AppName>*?Yes*?Yes*?Default
3=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Actual*?SystemComponent*?REG_DWORD*?1*?Yes*?Yes*?Default
'@
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-hidden-custom-arp.exe') -AdditionalSetup $AdditionalSetup -AdditionalRegistry $AdditionalRegistry
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.AppsAndFeaturesEntries | Should -BeNullOrEmpty
  }

  It 'keeps multiple visible custom uninstall keys ambiguous' {
    $AdditionalSetup = "Uninstall=0`r`nShowAddRemove=0"
    $AdditionalRegistry = @'
2=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\First.Actual*?DisplayName*?REG_SZ*?First Actual*?Yes*?Yes*?Default
3=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Second.Actual*?DisplayName*?REG_SZ*?Second Actual*?Yes*?Yes*?Default
'@
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-multiple-custom-arp.exe') -AdditionalSetup $AdditionalSetup -AdditionalRegistry $AdditionalRegistry
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.AppsAndFeaturesEntries | Should -HaveCount 2
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.ARP.MultipleCustomEntries'
  }

  It 'removes silent suggestions when compiled setup policy disables silent installation' {
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-no-silent.exe') -AdditionalSetup 'SetupParameters=-nosilent'
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.InstallModes | Should -Be @('interactive')
    $Info.InstallerSwitches.Contains('Silent') | Should -BeFalse
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Installability.SilentDisabled'
    ($Info.ExitCodeEvidence.GetEnumerator() | Where-Object Key -EQ 27).Value | Should -Match 'Silent installation'
  }

  It 'projects command scenario gates and documented ZIP extraction plans' {
    $Command = '0=ZIP:<SetupTempDir>\payload.zip*?<InstallDir>*?Hide*?After Installation*?Yes*?Any*?No'
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-command-policy.exe') -AdditionalSetup 'SetupParameters=-nocmdifsilent -nocmdifupdate' -AdditionalCommands $Command
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.CommandApplicability | Should -HaveCount 1
    $Info.CommandApplicability[0].Platform | Should -Be 'Any'
    $Info.CommandApplicability[0].RunsInSilent | Should -BeFalse
    $Info.CommandApplicability[0].RunsInUpdate | Should -BeFalse
    $Info.ExternalArchivePlans | Should -HaveCount 1
    $Info.ExternalArchivePlans[0].Kind | Should -Be 'ZipCommand'
    $Info.ExternalArchivePlans[0].ArchiveExpression | Should -Be '<SetupTempDir>\payload.zip'
  }

  It 'evaluates literal command comparisons and preserves runtime-dependent registry operations' {
    $Command = '0=IF "<AppName>"="Example Actual"*?HALT*?Hide*?Before Installation*?Yes*?Any*?No'
    $Registry = '2=HKCU\Software\Example*?DynamicValue*?REG_SZ*?<RuntimeValue>*?Yes*?No*?Default'
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-operation-grammar.exe') -AdditionalCommands $Command -AdditionalRegistry $Registry
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.Commands[0].ConditionState | Should -Be 'True'
    $Info.Commands[0].ActionKind | Should -Be 'HALT'
    $Info.CommandApplicability[0].MayStopCurrentPhase | Should -BeTrue
    $Info.CommandApplicability[0].RequiresRuntimeEvaluation | Should -BeFalse
    $Info.RegistryOperations | Should -HaveCount 3
    $Info.RegistryOperations[-1].CanProject | Should -BeFalse
    $Info.RegistryWrites | Should -HaveCount 2
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Registry.RuntimeExpression'
  }

  It 'leaves unknown SystemType enum values unresolved' {
    $AdditionalSetup = "InstallLevel=1`r`nInstallDir=<ProgramFiles>\<AppName>`r`nSystemType=7"
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-unknown-system-type.exe') -AdditionalSetup $AdditionalSetup
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.ArchitectureConfiguration.ConfigurationKey | Should -Be 'SystemType'
    $Info.ArchitectureConfiguration.LayoutEvidenceKnown | Should -BeFalse
    $Info.ArchitectureConfiguration.Uses64BitLayout | Should -BeNullOrEmpty
    $Info.RegistryView | Should -BeNullOrEmpty
    $Info.DefaultInstallLocation | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Architecture.UnknownConfiguration'
  }

  It 'maps the builder SystemType enum to its compiled filesystem and registry layout' -ForEach @(
    @{ Value = 0; Uses64BitLayout = $false; RegistryView = '32-bit'; InstallLocation = '%ProgramFiles(x86)%\Actual Installer VM Probe' }
    @{ Value = 1; Uses64BitLayout = $true; RegistryView = '64-bit'; InstallLocation = '%ProgramFiles%\Actual Installer VM Probe' }
    @{ Value = 2; Uses64BitLayout = $false; RegistryView = '32-bit'; InstallLocation = '%ProgramFiles(x86)%\Actual Installer VM Probe' }
  ) {
    $Path = Join-Path $Script:Builder98Root "SystemType\Type$Value\AIProbe-SystemType$Value.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "The controlled SystemType=$Value fixture is unavailable."; return }

    $Info = Get-ActualInstallerInfo -Path $Path

    $Info.ArchitectureConfiguration.ConfigurationValue | Should -Be ([string]$Value)
    $Info.ArchitectureConfiguration.Uses64BitLayout | Should -Be $Uses64BitLayout
    $Info.ArchitectureConfiguration.RegistryView | Should -Be $RegistryView
    $Info.DefaultInstallLocation | Should -Be $InstallLocation
    $Info.Diagnostics.Id | Should -Not -Contain 'ActualInstaller.Architecture.UnknownConfiguration'
  }

  It 'parses and extracts the metadata-first cabinet route' {
    $Fixture = New-TestActualInstallerCabinetFixture -Path (Join-Path $TestDrive 'actual-cabinet.exe')
    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.FormatGeneration | Should -Be 'Cabinet4'
    $Info.DisplayName | Should -Be 'Cabinet Actual'
    $Info.Scope | Should -Be 'machine'
    $Info.ProductCode | Should -Be 'Cabinet Actual'
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Cabinet Actual 4.8'
    $Info.Diagnostics.Id | Should -Not -Contain 'ActualInstaller.ARP.LegacyKeyUnresolved'
    $Files = @(Expand-ActualInstallerInstaller -Path $Fixture -DestinationPath (Join-Path $TestDrive 'actual-cabinet-output') -CollisionAction Rename)
    $Files | Should -HaveCount 1
    [IO.File]::ReadAllText($Files[0].FullName) | Should -Be 'cabinet payload'
  }

  It 'rejects cabinet sequences whose compiled lengths do not identify the payload' {
    $Fixture = New-TestActualInstallerCabinetFixture -Path (Join-Path $TestDrive 'actual-cabinet-length-mismatch.exe') -DeclaredLengthAdjustment 1

    Test-ActualInstaller -Path $Fixture | Should -BeFalse
    { Get-ActualInstallerInfo -Path $Fixture } | Should -Throw '*does not match logical file index*'
  }

  It 'rejects marker-only PE files' {
    $Fixture = Join-Path $TestDrive 'actual-marker.exe'
    [IO.File]::Copy((Join-Path $PSHOME 'pwsh.exe'), $Fixture, $true)
    Add-Content -LiteralPath $Fixture -Value 'Actual Installer aisetup.ini'
    Test-ActualInstaller -Path $Fixture | Should -BeFalse
  }

  It 'rejects duplicate physical ZIP indexes instead of selecting one arbitrarily' {
    $Fixture = New-TestActualInstallerZipFixture -Path (Join-Path $TestDrive 'actual-duplicate-index.exe') -DuplicatePayloadIndex
    Test-ActualInstaller -Path $Fixture | Should -BeFalse
    { Get-ActualInstallerInfo -Path $Fixture } | Should -Throw '*more than one physical ZIP entry*'
  }
}

Describe 'Actual Installer historical media' {
  It 'covers the metadata-first 3.x cabinet layout' {
    if (-not (Test-Path -LiteralPath $Script:Actual38)) { Set-ItResult -Skipped -Because 'The historical 3.8 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual38
    $Info.FormatGeneration | Should -Be 'Cabinet3'
    $Info.DisplayVersion | Should -Be '3.8'
    $Info.Scope | Should -Be 'machine'
    $Info.ProductCode | Should -BeNullOrEmpty
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 50
  }

  It 'covers the metadata-first 4.x cabinet layout' {
    if (-not (Test-Path -LiteralPath $Script:Actual48)) { Set-ItResult -Skipped -Because 'The historical 4.8 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual48
    $Info.FormatGeneration | Should -Be 'Cabinet4'
    $Info.BuilderVersion | Should -Be '4.8'
    $Info.ProductCode | Should -Be 'Actual Installer'
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Actual Installer 4.8'
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 53
  }

  It 'extracts the hybrid Setup EXE plus Data output generated by the 9.6 builder' {
    $Installer = Join-Path $Script:Builder96Root 'ExternalData\AIProbe-External.exe'
    $Companion = Join-Path $Script:Builder96Root 'ExternalData\AIProbe-External.7z'
    if (-not (Test-Path -LiteralPath $Installer) -or -not (Test-Path -LiteralPath $Companion)) { Set-ItResult -Skipped -Because 'The controlled 9.6 external-data fixture is unavailable.'; return }

    $Info = Get-ActualInstallerInfo -Path $Installer -CompanionFile $Companion
    $Output = Join-Path $TestDrive 'actual-builder-external'
    $Files = @(Expand-ActualInstallerInstaller -Path $Installer -CompanionFile $Companion -DestinationPath $Output -CollisionAction Error)

    $Info.FormatGeneration | Should -Be 'Zip6Plus'
    $Info.MediaInfo.PackageType | Should -Be '1'
    $Info.MediaInfo.CompanionDataFile | Should -Be 'AIProbe-External.7z'
    $Info.Architecture | Should -Be 'x64'
    $Info.PayloadArchitectures | Should -Be @('x64')
    $Info.CompanionPayloadCatalog | Should -HaveCount 2
    $Info.InstalledPayloadCatalog | Should -HaveCount 4
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 2
    $Files | Should -HaveCount 4
    [IO.File]::ReadAllText((Join-Path $Output 'Probe.txt')) | Should -Be 'Actual Installer controlled payload'
  }

  It 'matches the VM-validated 5.2 ARP identity and metadata-last cabinet layout' {
    if (-not (Test-Path -LiteralPath $Script:Actual52)) { Set-ItResult -Skipped -Because 'The historical 5.2 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual52
    $Info.FormatGeneration | Should -Be 'Cabinet5'
    $Info.ProductCode | Should -Be '{318020E9-4E14-DAB0-1CE4-2EE91C6FF5D0}'
    $Info.DisplayName | Should -Be 'Actual Installer'
    $Info.DisplayVersion | Should -Be '5.2'
    $Info.Publisher | Should -Be 'Softeza Development'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Actual Installer'
    $Info.UninstallString | Should -Be '%ProgramFiles(x86)%\Actual Installer\Uninstall.exe'
    $Info.UninstallerCommandEvidence.RegistryUninstallString | Should -Be '%ProgramFiles(x86)%\Actual Installer\Uninstall.exe'
    $Info.UninstallerCommandEvidence.RegistryStoresQuietUninstallString | Should -BeFalse
    $Info.UninstallerCommandEvidence.SilentCommand | Should -Be '"%ProgramFiles(x86)%\Actual Installer\Uninstall.exe" /S'
    $Info.DisplayIcon | Should -Be '%ProgramFiles(x86)%\Actual Installer\AInstaller.exe'
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 51
    $Info.GeneratedOutputs | Should -HaveCount 1
    $Info.GeneratedOutputs[0].Kind | Should -Be 'DuplicateLogicalRecord'
    $Info.Diagnostics.Id | Should -Not -Contain 'ActualInstaller.Extraction.GeneratedTemplateOutput'
    $Info.Operations.Files[0].PolicyEncoding | Should -Be 'LegacyFields'
  }

  It 'covers the first verified numbered-ZIP generation' {
    if (-not (Test-Path -LiteralPath $Script:Actual66)) { Set-ItResult -Skipped -Because 'The historical 6.6 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual66
    $Info.FormatGeneration | Should -Be 'Zip6Plus'
    $Info.BuilderVersion | Should -Be '6.6'
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 42
    $Info.Operations.Files[0].PolicyEncoding | Should -Be 'SplitIndex'
    $Info.Operations.Files[0].IfExistsMode | Should -Be 'Overwrite'
  }

  It 'covers the SystemType-based 6.7 configuration generation' {
    if (-not (Test-Path -LiteralPath $Script:Actual67)) { Set-ItResult -Skipped -Because 'The historical 6.7 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual67
    $Info.BuilderVersion | Should -Be '6.7'
    $Info.ArchitectureConfiguration.ConfigurationKey | Should -Be 'SystemType'
    $Info.RegistryView | Should -Be '32-bit'
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 42
  }

  It 'does not fabricate dual scope for a machine-only 8.0 project' {
    if (-not (Test-Path -LiteralPath $Script:Actual80)) { Set-ItResult -Skipped -Because 'The historical 8.0 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual80
    $Info.Scope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.FileExtensions | Should -Contain 'aip'
    $Info.GeneratedUninstaller.TemplateEntry | Should -Be 'AUninstall.exe'
    $Info.GeneratedUninstaller.CanReconstruct | Should -BeTrue
    $Info.GeneratedUninstaller.ReconstructionMode | Should -Be 'ExactCopy'
    $Info.Operations.Files[0].PolicyEncoding | Should -Be 'CompactIndexes'
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Extraction.GeneratedHelperExactCopy'
    $Info.Diagnostics.Id | Should -Not -Contain 'ActualInstaller.Extraction.GeneratedTemplateOutput'
    $TemplateOutput = Join-Path $TestDrive 'actual-80-metadata'
    $Template = @(Expand-ActualInstallerInstaller -Path $Script:Actual80 -DestinationPath $TemplateOutput -MetadataEntries -Name '*AUninstall.exe' -CollisionAction Error)
    $Template | Should -HaveCount 1
    $Template[0].Length | Should -Be 698880
    $InstalledOutput = Join-Path $TestDrive 'actual-80-installed'
    $Installed = @(Expand-ActualInstallerInstaller -Path $Script:Actual80 -DestinationPath $InstalledOutput -Name 'Uninstall.exe' -CollisionAction Error)
    $Installed | Should -HaveCount 1
    (Get-FileHash -LiteralPath $Installed[0].FullName).Hash | Should -Be (Get-FileHash -LiteralPath $Template[0].FullName).Hash
  }

  It 'decodes encoded 8.x command fields without changing plain control fields' -ForEach @(
    @{ FileName = '20210227072937-aisetup.exe'; Version = '8.2' }
    @{ FileName = '20211026215016-aisetup.exe'; Version = '8.4' }
  ) {
    $Path = Join-Path $Script:WaybackRoot $FileName
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "The historical $Version fixture is unavailable."; return }
    $Info = Get-ActualInstallerInfo -Path $Path
    $Info.Commands[0].File | Should -Be '<InstallDir>\Data\Feed.exe'
    $Info.Commands[0].Parameters | Should -Be '<appversion>'
    $Info.Commands[0].Timing | Should -Be 'Before Uninstallation'
    $Info.Commands[0].EncodedFieldIndexes | Should -Be @(0, 1)
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Configuration.EncodedCommandsDecoded'
  }

  It 'covers the plain-command 8.3 variant independently from encoded 8.x records' {
    if (-not (Test-Path -LiteralPath $Script:Actual83)) { Set-ItResult -Skipped -Because 'The historical 8.3 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual83
    $Info.BuilderVersion | Should -Be '8.3'
    $Info.Commands[0].File | Should -Be '<InstallDir>\Data\Feed.exe'
    $Info.Commands[0].EncodedFieldIndexes | Should -BeNullOrEmpty
  }

  It 'rejects the known truncated 8.2 Wayback capture' {
    if (-not (Test-Path -LiteralPath $Script:Actual82Truncated)) { Set-ItResult -Skipped -Because 'The truncated historical 8.2 fixture is unavailable.'; return }
    Test-ActualInstaller -Path $Script:Actual82Truncated | Should -BeFalse
    { Get-ActualInstallerInfo -Path $Script:Actual82Truncated } | Should -Throw '*Expected one Actual Installer setup configuration*'
  }

  It 'keeps an online dynamic version unresolved while exposing its dual-scope policy' {
    if (-not (Test-Path -LiteralPath $Script:Actual10)) { Set-ItResult -Skipped -Because 'The online 10.0 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual10
    $Info.BuilderVersion | Should -Be '9.8'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.Scope | Should -BeNullOrEmpty
    $Info.DefaultScope | Should -Be 'user'
    $Info.DefaultInstallLocation | Should -Be '%APPDATA%\Actual Installer'
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Metadata.DynamicVersion'
    $Info.Commands[0].File | Should -Be 'DOWNLOAD:https://www.actualinstaller.com/download/data-free<V>.7z'
    $Info.Commands[1].Parameters | Should -Be 'x "<SetupTempDir>\data<V>.7z"  -o"<InstallDir>" -aoa'
    $Info.Variables[0].SourceKind | Should -Be 'GETURL'
    $Info.Variables[0].Source | Should -Be 'https://www.actualinstaller.com/update.txt'
    $Info.MediaInfo.ExternalDownloads | Should -HaveCount 1
    $Info.MediaInfo.ExternalDownloads[0].Url | Should -Be 'https://www.actualinstaller.com/download/data-free<V>.7z'
    $Info.ExternalArchivePlans | Should -HaveCount 1
    $Info.ExternalArchivePlans[0].Kind | Should -Be 'SevenZipCommand'
    $Info.ExternalArchivePlans[0].ArchiveExpression | Should -Be '<SetupTempDir>\data<V>.7z'
    $Info.ExternalArchivePlans[0].DestinationExpression | Should -Be '<InstallDir>'
    $Info.CommandApplicability[0].Platform | Should -Be 'Any'
    $Info.CommandApplicability[0].RunsInSilent | Should -BeTrue
    $Info.CommandApplicability[0].ConditionState | Should -Be 'Unconditional'
    $Info.Diagnostics.Id | Should -Contain 'ActualInstaller.Extraction.RuntimeDownload'
    $Info.ExitCodeEvidence.Count | Should -Be 30
  }

  It 'parses the separate Actual Updater product without builder-specific hardcoding' {
    if (-not (Test-Path -LiteralPath $Script:ActualUpdater50)) { Set-ItResult -Skipped -Because 'The current Actual Updater fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:ActualUpdater50
    $Info.FormatGeneration | Should -Be 'Zip6Plus'
    $Info.BuilderVersion | Should -Be '9.6'
    $Info.DisplayName | Should -Be 'Actual Updater Free'
    $Info.DisplayVersion | Should -Be '5.0'
    $Info.ProductCode | Should -Be '{FCB1CDDE-F768-4D43-B1A1-BC019502DBC5}'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Actual Updater'
  }

  It 'covers fixed-version 9.6 builder media independently from the online wrapper' {
    if (-not (Test-Path -LiteralPath $Script:Actual96Fixed)) { Set-ItResult -Skipped -Because 'The fixed 9.6 fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:Actual96Fixed
    $Info.FormatGeneration | Should -Be 'Zip6Plus'
    $Info.BuilderVersion | Should -Be '9.6'
    $Info.DisplayName | Should -Be 'Actual Installer Free'
    $Info.DisplayVersion | Should -Be '9.6'
    $Info.ProductCode | Should -Be '{318020E9-4E14-DAB0-1CE4-2EE91C6FF5D0}'
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 43
  }

  It 'covers the archived 9.2-built Actual Updater media' {
    if (-not (Test-Path -LiteralPath $Script:ActualUpdater481)) { Set-ItResult -Skipped -Because 'The archived Actual Updater fixture is unavailable.'; return }
    $Info = Get-ActualInstallerInfo -Path $Script:ActualUpdater481
    $Info.BuilderVersion | Should -Be '9.2'
    $Info.DisplayName | Should -Be 'Actual Updater'
    $Info.DisplayVersion | Should -Be '4.8.1'
    $Info.ProductCode | Should -Be '{FCB1CDDE-F768-4D43-B1A1-BC019502DBC5}'
    @($Info.PayloadCatalog | Where-Object Available) | Should -HaveCount 12
    $Info.GeneratedUninstaller.TemplateEntry | Should -Be 'Uninstall.exe'
    $Info.GeneratedUninstaller.FileRecordIndex | Should -BeNullOrEmpty
  }

  It 'rejects the standalone Actual Downloader sibling product' {
    if (-not (Test-Path -LiteralPath $Script:ActualDownloader)) { Set-ItResult -Skipped -Because 'The Actual Downloader fixture is unavailable.'; return }
    Test-ActualInstaller -Path $Script:ActualDownloader | Should -BeFalse
    { Get-ActualInstallerInfo -Path $Script:ActualDownloader } | Should -Throw '*does not contain a supported Actual Installer container sequence*'
  }
}
