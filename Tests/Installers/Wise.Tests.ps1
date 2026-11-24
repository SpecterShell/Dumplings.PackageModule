. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  . (Join-Path $Script:DumplingsModuleRoot 'Index.ps1')

  $Script:FixtureDirectory = $TestDrive
  $ProgressPreference = 'SilentlyContinue'
  $Script:NavigatorX86 = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'NavigatorPlus-1.42-x86.exe') -Uri 'https://cdn0.scrvt.com/0b415e9fe7995370c62ceab2d1317f1c/ac1c4f60c0ee9dd9/62c370419488/Navigator_1.42_32.exe'
  $Script:NavigatorX64 = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'NavigatorPlus-1.42-x64.exe') -Uri 'https://cdn0.scrvt.com/0b415e9fe7995370c62ceab2d1317f1c/4e834844313c597e/adfaf567ee0f/Navigator_1.42_64.exe'
  $Script:WiseBuilderRoot = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Wise\ArchiveOrg\Extracted'

  function Get-WiseFixture {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$Url
    )
    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url
  }
}

Describe 'Wise MSI wrapper parser' {
  It 'Should parse TI Connect through its validated embedded MSI' {
    $Installer = Get-WiseFixture -Name 'TI-Connect-4.0.0.218.exe' -Url 'https://education.ti.com/download/en/ed-tech/14D11109C9F44D55B9BBF65E5A62E7F1/A885DD53BEC14496971FE5A42F1014CF/TI-Connect-4.0.0.218.exe'
    $Info = Get-WiseInfo -Path $Installer

    $Info.InstallerType | Should -Be 'exe'
    $Info.DisplayVersion | Should -Be '4.0.0.218'
    $Info.Publisher | Should -Be 'Texas Instruments Inc.'
    $Info.ProductCode | Should -Be '{D06BA64C-4447-49B4-B99D-E85BEA9E1035}'
    $Info.UpgradeCode | Should -Be '{FCEEDA79-4099-4C10-B717-F72EF53CCDA9}'
    $Info.Scope | Should -Be 'machine'
    $Info.NestedInstallerBuilder | Should -Be 'Wise'
    $Info.InstallLocationProperty | Should -Be 'INSTALLDIR'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.FileExtensions | Should -Contain '8xp'
    $Info.ContainerRoute | Should -Be 'WiseSection/Msi'
    $Info.FormatProfile | Should -Be 'WiseSectionMsi'
    Test-WiseInstaller -Path $Installer | Should -BeTrue
  }

  It 'Should parse the non-silent NavigatorPlus <Architecture> prerequisite wrapper' -ForEach @(
    @{ Architecture = 'x86'; PathVariable = 'NavigatorX86'; Sha256 = 'CD1DF5C8CC990548D1E4C8EC5FD0DB12597C11C8D7F4E760287B08F5FA0716E7'; MsiSha256 = 'A479C35EBCE11739BFB56E2A4E68C4D2199AEA698390E648EAF9219769D25DF0'; MsiLength = 40653824 }
    @{ Architecture = 'x64'; PathVariable = 'NavigatorX64'; Sha256 = '7D740E864BCE3984E74FD5FC816B09EDB4A25700428551CD98B890F6200EE1CC'; MsiSha256 = '6DE58160CCA1612E7158B2644505929E1A0CEB99BCC7B4F240ACCD30EDF8C936'; MsiLength = 41027584 }
  ) {
    $Path = Get-Variable -Name $PathVariable -Scope Script -ValueOnly
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Path -Sha256 $Sha256)) { Set-ItResult -Skipped -Because "The NavigatorPlus $Architecture fixture is unavailable."; return }

    $Info = Get-WiseInfo -Path $Path
    $Info.ContainerRoute | Should -Be 'ResourceLauncher/WiseScript'
    $Info.FormatProfile | Should -Be 'SourceOverlay'
    $Info.BuilderVersion | Should -Be '9.02'
    $Info.WiseVariant | Should -Be 'WiseScript MSI prerequisite wrapper'
    $Info.DisplayName | Should -Be 'FP-PostBase'
    $Info.DisplayVersion | Should -Be '1.42.0.0'
    $Info.ProductCode | Should -Be '{6F2CC443-74A4-4D1B-AEDE-DBBD8322DDAF}'
    $Info.UpgradeCode | Should -Be '{A3C16FDC-9316-48C7-8805-449EFF7F2F5E}'
    $Info.ElevationRequirement | Should -Be 'elevationRequired'
    $Info.InstallModes | Should -Be @('interactive')
    $Info.InstallerSwitches.Count | Should -Be 0
    $Info.PayloadCatalog | Should -HaveCount 4
    $Info.Diagnostics.Id | Should -Contain 'Wise.Installability.NestedMsiInteractiveOnly'

    $Output = Join-Path $TestDrive "NavigatorPlus-$Architecture.msi"
    $Extracted = Expand-WiseInstaller -Path $Path -DestinationPath $Output -CollisionAction Error
    $Extracted.Length | Should -Be $MsiLength
    (Get-FileHash -LiteralPath $Extracted.FullName -Algorithm SHA256).Hash | Should -Be $MsiSha256
  }

  It 'Should identify historical NE Wise overlays without fabricating metadata' -ForEach @(
    @{ Version = '5'; RelativePath = 'DISK1\WISE5.EXE'; Sha256 = 'E54AEA1FD14C4DDFA6DD3B5E0BF0F34BC9207769DAA026C2E5D407B5D3975B31'; ScriptSupported = $false }
    @{ Version = '6'; RelativePath = 'DISK2\WISE6.EXE'; Sha256 = 'B3D6D1007351C0BF0FDEDD9235E428E2BEE066BCF8774B0C4EBF3A0E6BBCEFDE'; ScriptSupported = $false }
    @{ Version = '7.01'; RelativePath = 'DISK3\WISE701.EXE'; Sha256 = '33C395771CFBDDF220D5BEF5E05F327171033B9DCE982648E26A7FA06B7EDABF'; ScriptSupported = $true }
  ) {
    $Path = Join-Path $Script:WiseBuilderRoot $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Path -Sha256 $Sha256)) { Set-ItResult -Skipped -Because "The Wise $Version builder fixture is unavailable."; return }

    $Info = Get-WiseInfo -Path $Path
    $Info.ContainerRoute | Should -Be 'NewExecutable/WiseScript'
    Test-WiseInstaller -Path $Path | Should -BeTrue
    if ($ScriptSupported) {
      $Info.FormatProfile | Should -Be 'ExtendedOverlay'
      $Info.BuilderVersion | Should -Be '7.01'
      $Info.InstallModes | Should -Be @('interactive', 'silent')
      $Info.InstallerSwitches.Silent | Should -Be '/S'
      $Info.InstallerSwitches.SilentWithProgress | Should -Be '/S'
      $Info.PayloadCatalog.Count | Should -BeGreaterThan 500
      $Info.AppsAndFeaturesEvidence[0].ProductCode | Should -Be 'Wise InstallMaster'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.Diagnostics.Id | Should -Contain 'Wise.Metadata.ScriptArpConditionsRequireValidation'
    } else {
      $Info.FormatProfile | Should -Be 'LegacyOverlay'
      $Info.PayloadCatalog | Should -BeNullOrEmpty
      $Info.UnresolvedFields | Should -Contain 'ProductCode'
      $Info.Diagnostics.Id | Should -Contain 'Wise.Metadata.ScriptModelUnsupported'
    }
  }
}

Describe 'WinGet analyzer Wise routing' {
  It 'Should prefer the Wise parser over generic EXE heuristics' {
    $Installer = Get-WiseFixture -Name 'TI-Connect-4.0.0.218.exe' -Url 'https://education.ti.com/download/en/ed-tech/14D11109C9F44D55B9BBF65E5A62E7F1/A885DD53BEC14496971FE5A42F1014CF/TI-Connect-4.0.0.218.exe'
    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'Wise' -and $_.Success } | Select-Object -First 1

    $Result.Result.Family | Should -Be 'Wise'
    $Result.Result.ProductCode | Should -Be '{D06BA64C-4447-49B4-B99D-E85BEA9E1035}'
    $Result.Result.SuggestedManifestFields.InstallerSwitches.InstallLocation | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
  }

  It 'Should not suggest silent switches for the NavigatorPlus prerequisite route' {
    if (-not (Test-Path -LiteralPath $Script:NavigatorX86)) { Set-ItResult -Skipped -Because 'The NavigatorPlus x86 fixture is unavailable.'; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:NavigatorX86
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'Wise' -and $_.Success } | Select-Object -First 1
    $Fields = $Result.Result.SuggestedManifestFields

    $Fields.InstallerType | Should -Be 'exe'
    $Fields.ProductCode | Should -Be '{6F2CC443-74A4-4D1B-AEDE-DBBD8322DDAF}'
    $Fields.ElevationRequirement | Should -Be 'elevationRequired'
    $Fields.InstallModes | Should -Be @('interactive')
    $Fields.PSObject.Properties.Name | Should -Not -Contain 'InstallerSwitches'
    $EntryNames = @($Fields.AppsAndFeaturesEntries[0].Keys)
    @($EntryNames | Where-Object { $_ -notin @('ProductCode', 'UpgradeCode', 'InstallerType') }).Count | Should -Be 0
    $EntryNames | Should -Not -Contain 'InstallerBuilder'
  }
}
