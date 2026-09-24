. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  $Script:LegacyNativeInstaller = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'AKInstaller-4.4.505.exe')
  $Script:NativeInstaller = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'AKInstaller-6.6.225.exe')
  $Script:ClassicNativeInstaller = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'IncCopy-3.0.exe')
  $Script:HistoricalClassicNativeInstaller = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Update-Download-Tool-1.9.10.exe')
  $Script:HistoricalProductMsiBootstrapper = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'AKPackIt-1.8.6.exe')
  $Script:LegacyMsiBootstrapper = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'AKInstallerMSI-3.5.1.exe')
  $Script:MsiBootstrapper = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'AKInstallerMSI-5.6.700.exe')
  $Script:VendorMsiBootstrapper = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Update-Download-Tool-2.9.610.exe')
  $Script:ProductionMsiBootstrapper = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'regibox-3.0.3-18428.exe')
  $Script:DirectMsiBootstrapper = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'regipay-5.0.0-233.x86.exe')
  . (Join-Path $Script:DumplingsModuleRoot 'Index.ps1')
}

Describe 'AKInstaller structural routes' {
  It 'parses the legacy KAPI table transform without applying the modern RC4 profile' {
    if (-not (Test-Path -LiteralPath $Script:LegacyNativeInstaller)) { Set-ItResult -Skipped -Because 'The legacy AKInstaller native fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:LegacyNativeInstaller

    $Info.Route | Should -Be 'AKInstaller/NativeLegacy'
    $Info.FormatGeneration | Should -Be 'NativeLegacyTable3'
    $Info.ProjectTable.StringProfile | Should -Be 'LegacyXor'
    $Info.EngineVersion | Should -Be 20
    $Info.DisplayName | Should -Be 'AKInstaller 4.4.505'
    $Info.DisplayVersion | Should -Be '4.4.505'
    $Info.Publisher | Should -Be 'AKApplications'
    $Info.ProductCode | Should -Be '{53D65CCA-C6BB-487C-B4EB-C9DE6023CD52}'
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.RequestedExecutionLevel | Should -Be 'requireAdministrator'
    $Info.ElevationRequirement | Should -Be 'elevationRequired'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\AKApplications\AKInstaller'
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.InstallerSwitches.Silent | Should -Be '/silent 1 /NoReboot'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/silent 1 /NoReboot'
    $Info.PayloadFiles.Path | Should -Contain 'AKInstaller.exe'
    $Info.FileExtensions | Should -Contain 'stp'
    $Info.FileExtensions | Should -Contain 'rcc'
    $Info.UnresolvedFields | Should -BeNullOrEmpty
  }

  It 'parses the classic native GZip catalog without assigning modern switches' {
    if (-not (Test-Path -LiteralPath $Script:ClassicNativeInstaller)) { Set-ItResult -Skipped -Because 'The classic AKInstaller native fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:ClassicNativeInstaller

    $Info.Route | Should -Be 'AKInstaller/NativeClassicGZip'
    $Info.FormatGeneration | Should -Be 'NativeClassicGZipTable3'
    $Info.DisplayName | Should -Be 'IncCopy'
    $Info.ProductVersion | Should -Be '3.0'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.Publisher | Should -BeNullOrEmpty
    $Info.CompiledPublisher | Should -Be 'Andreas Kapust'
    $Info.ProductCode | Should -Be 'IncCopy'
    $Info.Scope | Should -Be 'machine'
    $Info.PackageArchitecture | Should -Be 'x86'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\IncCopy'
    $Info.UninstallString | Should -Be '%WINDIR%\AKDeInstall.exe "/%ProgramFiles%\IncCopy\"'
    $Info.DisplayIcon | Should -Be '%ProgramFiles%\IncCopy\IncCopy.exe'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.AppsAndFeaturesEntries | Should -HaveCount 1
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'IncCopy'
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'IncCopy'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'DisplayVersion'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'Publisher'
    $Info.InstallModes | Should -Be @('interactive')
    $Info.InstallerSwitches.Count | Should -Be 0
    $Info.DocumentedReturnCodes | Should -BeNullOrEmpty
    $Info.PayloadFiles.Path | Should -Contain 'IncCopy.exe'
    $Info.Diagnostics.Id | Should -Contain 'AKInstaller.Classic.CommandLineBehaviorUnresolved'
  }

  It 'parses every classic file row when a size begins with a typed-cell byte' {
    if (-not (Test-Path -LiteralPath $Script:HistoricalClassicNativeInstaller)) { Set-ItResult -Skipped -Because 'The historical UDT fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:HistoricalClassicNativeInstaller

    $Info.Route | Should -Be 'AKInstaller/NativeClassicGZip'
    $Info.DisplayName | Should -Be 'Update-Download-Tool'
    $Info.ProductName | Should -Be 'Update-Download-Tool'
    $Info.ProductVersion | Should -Be '1.9.10'
    $Info.DisplayVersion | Should -Be '1.7'
    $Info.Publisher | Should -BeNullOrEmpty
    $Info.CompiledPublisher | Should -Be 'Andreas Kapust'
    $Info.ProductCode | Should -Be 'UDTMaker'
    $Info.PackageArchitecture | Should -Be 'x86'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Update-Download-Tool'
    $Info.UninstallString | Should -Be '%WINDIR%\AKDeInstall.exe "/%ProgramFiles%\Update-Download-Tool\"'
    $Info.DisplayIcon | Should -Be '%ProgramFiles%\Update-Download-Tool\\UDTMaker.exe'
    @($Info.ProjectTable.Files | Where-Object Class -CEQ 'Installed').Count | Should -Be 16
    $Info.PayloadFiles.Path | Should -Contain 'UDTMaker.exe'
    ($Info.PayloadFiles | Where-Object FileName -CEQ 'UDTMaker.exe').Length | Should -Be 978944
    ($Info.PayloadFiles | Where-Object SizeMatchesPhysical -CEQ $false) | Should -BeNullOrEmpty
    $Info.ProjectTable.MalformedRecords | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -BeNullOrEmpty
    Read-ProductVersionFromAKInstaller -Path $Script:HistoricalClassicNativeInstaller | Should -Be '1.9.10'
    $Analysis = Get-InstallerAnalysis -Path $Script:HistoricalClassicNativeInstaller
    ($Analysis.ParserResults | Where-Object Name -CEQ 'AKInstaller').Result.ProductVersion | Should -Be '1.9.10'
  }

  It 'parses native project, ARP, association, and payload evidence' {
    if (-not (Test-Path -LiteralPath $Script:NativeInstaller)) { Set-ItResult -Skipped -Because 'The AKInstaller native fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:NativeInstaller

    $Info.Route | Should -Be 'AKInstaller/Native'
    $Info.FormatGeneration | Should -Be 'NativeTable3'
    $Info.DisplayName | Should -Be 'AKInstaller 6.6.225'
    $Info.DisplayVersion | Should -Be '6.6.225'
    $Info.Publisher | Should -Be 'AKApplications'
    $Info.ProductCode | Should -Be '{53D65CCA-C6BB-487C-B4EB-C9DE6023CD52}'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\AKApplications\AKInstaller'
    $Info.UninstallString | Should -Be '"%ProgramFiles%\AKApplications\AKInstaller\{53D65CCA-C6BB-487C-B4EB-C9DE6023CD52}\AKDeInstall.exe" /x'
    $Info.DisplayIcon | Should -Be '%ProgramFiles%\AKApplications\AKInstaller\AkInstaller.exe'
    $Info.FileExtensions | Should -Contain 'stp'
    $Info.FileExtensions | Should -Contain 'rcc'
    $Info.PayloadFiles.Path | Should -Contain 'Tools\ToHex.exe'
    $Info.Shortcuts.Count | Should -BeGreaterThan 0
    $Info.IniFileOperations.Count | Should -BeGreaterThan 0
    $Info.ExecutedPayloads.Path | Should -Contain '%TEMP%\CA10\VC_redist.x86.exe'
    $Info.LaunchConditions.Condition | Should -Contain 'UserPrivileged >= 2'
    $Info.Permissions.Count | Should -BeGreaterThan 0
    $Info.DirectoryAttributeOperations.Attributes | Should -Contain 'Normal'
    $Info.DirectoryAttributeOperations.Attributes | Should -Contain 'Hidden'
    $Info.CompiledProperties.Name | Should -Contain 'EXP_NextID'
    $Info.ExtensionModules.Identifier | Should -Contain 'EXT_ISO19770_2'
    $Info.ExtensionModules.Identifier | Should -Contain 'EXT_MicroPackage'
    $Info.FileOperations.Operation | Should -Contain 'DeleteFile'
    $Info.FileOperations.Operation | Should -Contain 'Rename'
    $Info.FileOperations.Operation | Should -Contain 'DeleteWildCard'
    $Info.FileOperations.Phase | Should -Contain 'BeforeInstallation'
    $Info.FileOperations.Phase | Should -Contain 'AfterInstallation'
    $Info.FileOperations.Phase | Should -Contain 'BeforeUninstallation'
    ($Info.FileOperations | Where-Object Index -EQ 2).Source | Should -Be '%ProgramFiles%\AKApplications\AKInstaller\Bilder'
    ($Info.FileOperations | Where-Object Index -EQ 2).Destination | Should -Be '%ProgramFiles%\AKApplications\AKInstaller\Pictures'
    ($Info.FileOperations | Where-Object Index -EQ 11).Condition | Should -Match 'ProductPreVersion'
    $Info.FileOperations.IsDecoded | Should -Not -Contain $false
    $Info.Diagnostics.Id | Should -Contain 'AKInstaller.Conditions.RuntimeEvaluationRequired'
    $Info.Diagnostics.Id | Should -Contain 'AKInstaller.SystemEffects.ExtensionSideEffectsOpaque'
    $Info.ProjectTable.MalformedRecords | Should -BeNullOrEmpty
    $Info.ProjectTable.DuplicateRecords | Should -BeNullOrEmpty
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be $Info.ProductCode
    $EstimatedSize = $Info.RegistryWrites | Where-Object { $_.Name -ceq 'EstimatedSize' } | Select-Object -First 1
    $EstimatedSize.Type | Should -Be 'REG_DWORD'
    $EstimatedSize.Value | Should -Be 66442
    $Info.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'
    $Info.Diagnostics.PSObject.Properties.Name | Should -Not -Contain 'Warnings'
  }

  It 'parses an encrypted AKInstallerMSI archive and delegates identity to its nested MSI' {
    if (-not (Test-Path -LiteralPath $Script:MsiBootstrapper)) { Set-ItResult -Skipped -Because 'The AKInstallerMSI wrapper fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:MsiBootstrapper

    $Info.Route | Should -Be 'AKInstallerMSI/Bootstrapper'
    $Info.FormatGeneration | Should -Be 'BootstrapperZip'
    $Info.DisplayName | Should -Be 'AKInstallerMSI'
    $Info.DisplayVersion | Should -Be '5.6.700'
    $Info.ProductCode | Should -Be '{87E55B71-19A8-4191-9D43-7566B969A6E9}'
    $Info.UpgradeCode | Should -Be '{85403575-E923-441D-B7EC-557903CF634C}'
    $Info.PrimaryNestedInstaller.Info.InstallerBuilder | Should -Be 'AKInstallerMSI'
    $Info.PrimaryNestedInstallerSelection | Should -Be 'ConfiguredProductCode'
    $Info.LaunchConditions.Count | Should -Be 2
    $Info.PrerequisitePayloads[0].Policy.Conditions[0].Expression | Should -Be 'VersionNT >= 601'
    $Info.PrerequisitePayloads[0].Policy.DetectionTests[0].Path | Should -Match 'VC\\Servicing'
    $Info.Diagnostics.Id | Should -Contain 'AKInstallerMSI.Dependencies.ConditionalPayloads'
    $Info.PayloadEncrypted | Should -BeTrue
    $Info.PSObject.Properties.Name | Should -Not -Contain 'Password'
    $Info.InstallModes | Should -Be @('interactive', 'silent', 'silentWithProgress')
    $Info.InstallerSwitches.Silent | Should -Be '/silent 2 /msiparam "REBOOT=ReallySuppress"'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/msilimitui 67 /msiparam "REBOOT=ReallySuppress"'
  }

  It 'parses a current vendor product built with AKInstallerMSI' {
    if (-not (Test-Path -LiteralPath $Script:VendorMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The current Update-Download-Tool fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:VendorMsiBootstrapper

    $Info.Route | Should -Be 'AKInstallerMSI/Bootstrapper'
    $Info.InstallerBuilderVersion | Should -Be '5.6.651'
    $Info.DisplayName | Should -Be 'Update-Download-Tool'
    $Info.DisplayVersion | Should -Be '2.9.610'
    $Info.Publisher | Should -Be 'AKApplications'
    $Info.ProductCode | Should -Be '{D221035D-65A1-4F93-8EDF-1F27F0243042}'
    $Info.UpgradeCode | Should -Be '{DAA0EC1E-BEB9-4E29-B955-E1354FF02839}'
    $Info.Scope | Should -Be 'machine'
    $Info.PackageArchitecture | Should -Be 'x86'
    $Info.DocumentedReturnCodes | Should -Contain 1603
    $Info.FileExtensions | Should -Contain 'udtl'
    $Info.FileExtensions | Should -Contain 'udtm'
  }

  It 'matches production AKInstallerMSI ARP and association evidence observed in the VM' {
    if (-not (Test-Path -LiteralPath $Script:ProductionMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The regibox AKInstallerMSI fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:ProductionMsiBootstrapper

    $Info.Route | Should -Be 'AKInstallerMSI/Bootstrapper'
    $Info.InstallerBuilderVersion | Should -Be '5.4.610'
    $Info.ProductCode | Should -Be '{623C51AB-E9A8-4E32-B216-ABDB2F999F61}'
    $Info.UpgradeCode | Should -Be '{331E081D-C0F9-4301-A95C-F31E8C22AD80}'
    $Info.DisplayName | Should -Be 'regibox'
    $Info.DisplayVersion | Should -Be '3.0.3'
    $Info.Publisher | Should -Be 'regify GmbH'
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.PackageArchitecture | Should -Be 'x86'
    $Info.FileExtensions | Should -Contain 'rgb'
    $Info.FileExtensions | Should -Contain 'rgbx'
    $Info.Diagnostics | Should -BeNullOrEmpty
  }

  It 'repairs and parses the historical AKI central-directory profile' {
    if (-not (Test-Path -LiteralPath $Script:LegacyMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The legacy AKInstallerMSI wrapper fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:LegacyMsiBootstrapper

    $Info.Route | Should -Be 'AKInstallerMSI/BootstrapperLegacy'
    $Info.FormatGeneration | Should -Be 'BootstrapperLegacyAkiZip'
    $Info.DisplayName | Should -Be 'AKInstallerMSI'
    $Info.DisplayVersion | Should -Be '3.5.1'
    $Info.ProductCode | Should -Be '{AB5F18A2-E141-4A24-B5A8-B7B7BB27C62D}'
    $Info.UpgradeCode | Should -Be '{85403575-E923-441D-B7EC-557903CF634C}'
    $Info.Scope | Should -Be 'machine'
    $Info.PackageArchitecture | Should -Be 'x86'
    $Info.PrimaryNestedInstaller.Info.InstallerBuilderVersion | Should -Be '3.5.1'
    $Info.PrimaryNestedInstallerSelection | Should -Be 'ConfiguredProductCode'
    $Info.LaunchConditions[0].AbortOnFailure | Should -BeTrue
    $Info.PrerequisitePayloads.Path | Should -Contain 'http://www.akapplications.com/sonstige/WindowsInstaller-KB893803-v2-x86.exe'
    $Info.PrerequisitePayloads[0].Policy.Conditions[0].Expression | Should -Match 'VersionNT'
    $Info.Diagnostics.Id | Should -Contain 'AKInstallerMSI.Dependencies.ExternalPayload'
    $Info.Diagnostics.Id | Should -Not -Contain 'AKInstallerMSI.Payload.ConfiguredFileMissing'
  }

  It 'parses a historical vendor product using the same AKI central-directory route' {
    if (-not (Test-Path -LiteralPath $Script:HistoricalProductMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The historical AKPackIt fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:HistoricalProductMsiBootstrapper

    $Info.Route | Should -Be 'AKInstallerMSI/BootstrapperLegacy'
    $Info.InstallerBuilderVersion | Should -Be '3.4.326'
    $Info.DisplayName | Should -Be 'AKPackIt'
    $Info.DisplayVersion | Should -Be '1.8.6'
    $Info.Publisher | Should -Be 'AKApplications'
    $Info.ProductCode | Should -Be '{79D6CD25-D883-43AA-87AB-1BF9459DAFE4}'
    $Info.UpgradeCode | Should -Be '{36E04CE3-378E-4548-8A18-008AEC9B9D96}'
    $Info.Scope | Should -Be 'machine'
    $Info.PackageArchitecture | Should -Be 'x86'
    $Info.PrimaryNestedInstallerSelection | Should -Be 'ConfiguredProductCode'
    $Info.Diagnostics | Should -BeNullOrEmpty
  }

  It 'recognizes a direct embedded MSI only through structured AKInstallerMSI builder evidence' {
    if (-not (Test-Path -LiteralPath $Script:DirectMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The AKInstallerMSI direct-MSI fixture is not cached.'; return }
    $Info = Get-AKInstallerInfo -Path $Script:DirectMsiBootstrapper

    $Info.Route | Should -Be 'AKInstallerMSI/EmbeddedMsi'
    $Info.FormatGeneration | Should -Be 'EmbeddedMsi'
    $Info.DisplayName | Should -Be 'regipay Client'
    $Info.DisplayVersion | Should -Be '5.0.0-233'
    $Info.ProductCode | Should -Be '{012D2F85-C9DC-4DCB-BD16-DDBA17BD6209}'
    $Info.UpgradeCode | Should -Be '{3A11F797-CAD6-43B8-886F-20ADD5CABAE3}'
    $Info.PrimaryNestedInstaller.InstallerBuilder | Should -Be 'AKInstallerMSI'
    $Info.PrimaryNestedInstaller.InstallerBuilderVersion | Should -Be '5.5.700'
    $Info.UnresolvedFields | Should -Contain 'Scope'
    $Info.Diagnostics.Id | Should -Contain 'AKInstallerMSI.Scope.ContextDependent'
    ($Info.Diagnostics | Where-Object Id -CEQ 'AKInstallerMSI.Scope.ContextDependent').Evidence.AllUsers | Should -Be '2'
  }

  It 'rejects marker-only PE files' {
    $Path = Join-Path $TestDrive 'marker-only.exe'
    Copy-Item -LiteralPath (Get-Process -Id $PID).Path -Destination $Path
    [IO.File]::AppendAllText($Path, '>AKINST_SETUP<>KAPI_SETUP<>INSTALLMSI_SETUP<')

    Test-AKInstaller -Path $Path | Should -BeFalse
  }

  It 'rejects a classic catalog whose declared member is not GZip data' {
    if (-not (Test-Path -LiteralPath $Script:ClassicNativeInstaller)) { Set-ItResult -Skipped -Because 'The classic AKInstaller native fixture is not cached.'; return }
    $Path = Join-Path $TestDrive 'corrupt-classic.exe'
    Copy-Item -LiteralPath $Script:ClassicNativeInstaller -Destination $Path
    $MarkerOffset = Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes('>KAPI_SETUP<')) -Reverse -Maximum 1 | Select-Object -First 1
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    try {
      $Footer = Read-BinaryBytes -Stream $Stream -Offset ($MarkerOffset - 24) -Count 24
      $PayloadOffset = [BitConverter]::ToUInt32($Footer, 16)
      $Stream.Position = $PayloadOffset
      $Stream.WriteByte(0)
    } finally { $Stream.Dispose() }

    Test-AKInstaller -Path $Path | Should -BeFalse
  }

  It 'rejects a malformed historical AKI central-directory record' {
    if (-not (Test-Path -LiteralPath $Script:LegacyMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The legacy AKInstallerMSI wrapper fixture is not cached.'; return }
    $Path = Join-Path $TestDrive 'corrupt-legacy-msi.exe'
    Copy-Item -LiteralPath $Script:LegacyMsiBootstrapper -Destination $Path
    $Offset = Find-BinaryPattern -Path $Path -Pattern ([byte[]](0x41, 0x4B, 0x49, 0x02)) -Maximum 128 | Select-Object -Last 1
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    try { $Stream.Position = $Offset; $Stream.WriteByte(0x42) } finally { $Stream.Dispose() }

    Test-AKInstaller -Path $Path | Should -BeFalse
  }

  It 'reconstructs custom, hidden, and multiple uninstall keys without forcing the compiled GUID' {
    InModuleScope AKInstaller {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKCU'; View = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.User.Product'; Name = 'DisplayName'; Value = 'User Product'; Create = $true },
        [pscustomobject]@{ Root = 'HKCU'; View = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.User.Product'; Name = 'Publisher'; Value = 'Example'; Create = $true },
        [pscustomobject]@{ Root = 'HKLM'; View = '64-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Machine.Product'; Name = 'DisplayName'; Value = 'Hidden Product'; Create = $true },
        [pscustomobject]@{ Root = 'HKLM'; View = '64-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Machine.Product'; Name = 'SystemComponent'; Value = 1; Create = $true }
      )

      $Info = Get-AKInstallerNativeArpInfo -RegistryWrite $Writes -CompiledProductCode '{NOT-THE-KEY}'

      $Info.VisibleEntries.Count | Should -Be 1
      $Info.VisibleEntries[0].ProductCode | Should -Be 'Custom.User.Product'
      $Info.VisibleEntries[0].Scope | Should -Be 'user'
      $Info.HiddenEntries.ProductCode | Should -Contain 'Hidden.Machine.Product'
      $Info.PrimaryEntry.ProductCode | Should -Be 'Custom.User.Product'
      $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'User Product'
    }
  }

  It 'reports malformed and duplicate typed table records without accepting their evidence' {
    InModuleScope AKInstaller {
      $Bytes = [Collections.Generic.List[byte]]::new()
      $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes('STPSETUPVERSION'))
      $Bytes.Add(3)
      $Bytes.AddRange([BitConverter]::GetBytes([uint32]20))
      foreach ($Value in 'First', 'Second') {
        $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes('STPLAA01A'))
        $Plain = [Text.Encoding]::Unicode.GetBytes($Value)
        $Cipher = ConvertFrom-AKInstallerRc4 -Bytes $Plain
        $Bytes.Add(1)
        $Bytes.AddRange([BitConverter]::GetBytes([uint32]$Cipher.Length))
        $Bytes.AddRange($Cipher)
        $Bytes.Add(0)
      }
      $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes('STPLAA99A'))
      $Bytes.Add(1)
      $Bytes.AddRange([BitConverter]::GetBytes([uint32]4096))

      $Table = Read-AKInstallerProjectTable -Bytes $Bytes.ToArray() -TableProfile ModernRc4

      $Table.Records['STPLAA01A'].Value | Should -Be 'First'
      $Table.DuplicateRecords.Count | Should -Be 1
      $Table.DuplicateRecords[0].Name | Should -Be 'STPLAA01A'
      $Table.MalformedRecords.Count | Should -Be 1
      $Table.MalformedRecords[0].Name | Should -Be 'STPLAA99A'
    }
  }

  It 'reads a classic file size without treating its low byte as a typed condition tag' {
    InModuleScope AKInstaller {
      $Bytes = [Collections.Generic.List[byte]]::new()
      $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes('STPSETUPVERSION'))
      $Bytes.Add(3)
      $Bytes.AddRange([BitConverter]::GetBytes([uint32]20))
      $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes('STPLC0BBBB'))
      foreach ($Value in 'payload.exe', 'A76', '<INSTALLDIR>\') {
        $Plain = [Text.Encoding]::GetEncoding(1252).GetBytes($Value)
        $Encoded = [byte[]]::new($Plain.Length)
        for ($Index = 0; $Index -lt $Plain.Length; $Index++) { $Encoded[$Index] = $Plain[$Index] -bxor 0x7B }
        $Bytes.Add(1)
        $Bytes.AddRange([BitConverter]::GetBytes([uint32]$Encoded.Length))
        $Bytes.AddRange($Encoded)
        $Bytes.Add(0)
      }
      # 0x101 deliberately starts with 0x01, which is also a typed-cell tag.
      $Bytes.AddRange([BitConverter]::GetBytes([uint32]0x101))

      $Table = Read-AKInstallerProjectTable -Bytes $Bytes.ToArray() -TableProfile LegacyXor

      $Table.Files.Count | Should -Be 1
      $Table.Files[0].FileName | Should -Be 'payload.exe'
      $Table.Files[0].ArchiveKey | Should -Be 'A76'
      $Table.Files[0].Condition | Should -BeNullOrEmpty
      $Table.Files[0].UnpackedSize | Should -Be 0x101
      $Table.MalformedRecords | Should -BeNullOrEmpty
    }
  }

  It 'decodes every source-backed native file-operation opcode and routing field' {
    InModuleScope AKInstaller {
      $Variables = [ordered]@{ INSTALLDIR = '%ProgramFiles%\Example' }
      $Cases = [ordered]@{
        '0DN<INSTALLDIR>\old.dll||Installed'       = @('SetupAndUpdate', 'DeleteFile', 'AfterInstallation')
        '1RV<INSTALLDIR>\old|<INSTALLDIR>\new|'    = @('SetupOnly', 'Rename', 'BeforeInstallation')
        '2CR<INSTALLDIR>\a|<INSTALLDIR>\b|'        = @('UpdateOnly', 'CopyFile', 'Rollback')
        '0MU<INSTALLDIR>\created||'                = @('SetupAndUpdate', 'MakeDir', 'BeforeUninstallation')
        '0-X<INSTALLDIR>\*.tmp||'                  = @('SetupAndUpdate', 'DeleteWildCard', 'AfterUninstallation')
        '0+N<INSTALLDIR>\*.dll|<INSTALLDIR>\copy|' = @('SetupAndUpdate', 'CopyWildCard', 'AfterInstallation')
        '0!N<INSTALLDIR>\empty||'                  = @('SetupAndUpdate', 'RemoveDirIfEmpty', 'AfterInstallation')
        '0FN<INSTALLDIR>\a|<INSTALLDIR>\b|'        = @('SetupAndUpdate', 'MoveFile', 'AfterInstallation')
        '0XN<INSTALLDIR>\*.txt|<INSTALLDIR>\tree|' = @('SetupAndUpdate', 'CopyMultiWildCard', 'AfterInstallation')
      }

      foreach ($Encoded in $Cases.Keys) {
        $Operation = ConvertFrom-AKInstallerFileOperation -Value $Encoded -Variables $Variables
        $Operation.Applicability | Should -Be $Cases[$Encoded][0]
        $Operation.Operation | Should -Be $Cases[$Encoded][1]
        $Operation.Phase | Should -Be $Cases[$Encoded][2]
        $Operation.IsDecoded | Should -BeTrue
        $Operation.IsStructurallyValid | Should -BeTrue
      }

      $Unknown = ConvertFrom-AKInstallerFileOperation -Value '0?N<INSTALLDIR>\a||' -Variables $Variables
      $Unknown.IsDecoded | Should -BeFalse
      $Unknown.EncodedOperation | Should -Be '0?N<INSTALLDIR>\a||'
    }
  }

  It 'uses one complete deterministic variable map for analysis and extraction' {
    InModuleScope AKInstaller {
      $Records = [ordered]@{}
      foreach ($Pair in ([ordered]@{
            STPLAA02A = 'Example'; STPLAA03A = '1.0'; STPLAA04A = 'Publisher'; STPLAAX4V = 'Example.Product'; STPLAA06A = '<PROGRAMDIR>\Example'
          }).GetEnumerator()) {
        $Records[$Pair.Key] = [pscustomobject]@{ Value = $Pair.Value }
      }
      $Table = [pscustomobject]@{
        Records = $Records
        Files   = @([pscustomobject]@{ Class = 'Installed'; FileName = 'helper.dll'; ArchiveKey = 'A02'; Destination = '<COMMONFILES>\Example'; Condition = ''; UnpackedSize = 1 })
      }

      $Context = Get-AKInstallerNativeVariableContext -Table $Table -Scope machine
      $Catalog = @(Get-AKInstallerNativePayloadCatalog -Table $Table -Variables $Context.Values -DefaultInstallLocation $Context.DefaultInstallLocation)

      $Context.DefaultInstallLocation | Should -Be '%ProgramFiles%\Example'
      $Context.Values.COMMONFILES | Should -Be '%CommonProgramFiles%'
      $Context.Values.LOCALAPPDATA | Should -Be '%LOCALAPPDATA%'
      $Context.Values.STARTMENU | Should -Be '%ProgramData%\Microsoft\Windows\Start Menu\Programs'
      $Catalog[0].Path | Should -Not -Match '<COMMONFILES>'
      $Catalog[0].Path | Should -Match '%CommonProgramFiles%'
    }
  }
}

Describe 'AKInstaller extraction and analysis integration' {
  It 'extracts native installed paths rather than opaque archive names' {
    if (-not (Test-Path -LiteralPath $Script:NativeInstaller)) { Set-ItResult -Skipped -Because 'The AKInstaller native fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'native'
    $Result = Expand-AKInstaller -Path $Script:NativeInstaller -DestinationPath $Output -Name 'Tools\ToHex.exe' -CollisionAction Error -MaximumExpandedBytes 1MB

    $Result.EntryCount | Should -Be 1
    Test-Path -LiteralPath (Join-Path $Output 'Tools\ToHex.exe') -PathType Leaf | Should -BeTrue
  }

  It 'extracts legacy native payloads with the route-specific table decoder' {
    if (-not (Test-Path -LiteralPath $Script:LegacyNativeInstaller)) { Set-ItResult -Skipped -Because 'The legacy AKInstaller native fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'legacy-native'
    $Result = Expand-AKInstaller -Path $Script:LegacyNativeInstaller -DestinationPath $Output -Name 'AKInstaller.exe' -CollisionAction Error -MaximumExpandedBytes 16MB

    $Result.EntryCount | Should -Be 1
    Test-Path -LiteralPath (Join-Path $Output 'AKInstaller.exe') -PathType Leaf | Should -BeTrue
  }

  It 'extracts installed files from the classic native GZip route' {
    if (-not (Test-Path -LiteralPath $Script:ClassicNativeInstaller)) { Set-ItResult -Skipped -Because 'The classic AKInstaller native fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'classic-native'
    $Result = Expand-AKInstaller -Path $Script:ClassicNativeInstaller -DestinationPath $Output -Name 'IncCopy.exe' -CollisionAction Error -MaximumExpandedBytes 1MB

    $Result.EntryCount | Should -Be 1
    (Get-Item -LiteralPath (Join-Path $Output 'IncCopy.exe')).Length | Should -Be 335872
  }

  It 'extracts a historical classic primary payload whose size begins with a typed-cell byte' {
    if (-not (Test-Path -LiteralPath $Script:HistoricalClassicNativeInstaller)) { Set-ItResult -Skipped -Because 'The historical UDT fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'historical-classic-native'
    $Result = Expand-AKInstaller -Path $Script:HistoricalClassicNativeInstaller -DestinationPath $Output -Name 'UDTMaker.exe' -CollisionAction Error -MaximumExpandedBytes 2MB

    $Result.EntryCount | Should -Be 1
    (Get-Item -LiteralPath (Join-Path $Output 'UDTMaker.exe')).Length | Should -Be 978944
  }

  It 'extracts logical nested MSI names from an encrypted wrapper' {
    if (-not (Test-Path -LiteralPath $Script:MsiBootstrapper)) { Set-ItResult -Skipped -Because 'The AKInstallerMSI wrapper fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'msi'
    $Result = Expand-AKInstaller -Path $Script:MsiBootstrapper -DestinationPath $Output -Name '*.msi' -CollisionAction Error -MaximumExpandedBytes 64MB

    $Result.EntryCount | Should -Be 1
    Test-Path -LiteralPath (Join-Path $Output 'Setup.msi') -PathType Leaf | Should -BeTrue
  }

  It 'extracts the nested MSI through the historical central-directory compatibility path' {
    if (-not (Test-Path -LiteralPath $Script:LegacyMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The legacy AKInstallerMSI wrapper fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'legacy-msi'
    $Result = Expand-AKInstaller -Path $Script:LegacyMsiBootstrapper -DestinationPath $Output -Name '*.msi' -CollisionAction Error -MaximumExpandedBytes 32MB

    $Result.EntryCount | Should -Be 1
    Test-Path -LiteralPath (Join-Path $Output 'Setup.msi') -PathType Leaf | Should -BeTrue
  }

  It 'extracts and bounds the direct embedded MSI route' {
    if (-not (Test-Path -LiteralPath $Script:DirectMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The direct AKInstallerMSI fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'direct-msi'

    { Expand-AKInstaller -Path $Script:DirectMsiBootstrapper -DestinationPath $Output -MaximumExpandedBytes 1 -CollisionAction Error } | Should -Throw '*byte output limit*'
    Test-Path -LiteralPath (Join-Path $Output 'embedded.msi') | Should -BeFalse

    $Result = Expand-AKInstaller -Path $Script:DirectMsiBootstrapper -DestinationPath $Output -MaximumExpandedBytes 16MB -CollisionAction Error
    $Result.EntryCount | Should -Be 1
    Test-Path -LiteralPath (Join-Path $Output 'embedded.msi') -PathType Leaf | Should -BeTrue
  }

  It 'preflights archive limits before writing native payloads' {
    if (-not (Test-Path -LiteralPath $Script:NativeInstaller)) { Set-ItResult -Skipped -Because 'The AKInstaller native fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'bounded-native'

    { Expand-AKInstaller -Path $Script:NativeInstaller -DestinationPath $Output -Name 'Tools\ToHex.exe' -MaximumExpandedBytes 1 -CollisionAction Error } | Should -Throw '*byte output limit*'
    Test-Path -LiteralPath $Output | Should -BeFalse
  }

  It 'applies collision policy only when a selected output already exists' {
    if (-not (Test-Path -LiteralPath $Script:NativeInstaller)) { Set-ItResult -Skipped -Because 'The AKInstaller native fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'collision-native'
    $Arguments = @{ Path = $Script:NativeInstaller; DestinationPath = $Output; Name = 'Tools\ToHex.exe'; MaximumExpandedBytes = 1MB }

    $null = Expand-AKInstaller @Arguments -CollisionAction Error
    { Expand-AKInstaller @Arguments -CollisionAction Error } | Should -Throw '*already exists*'
    $Renamed = Expand-AKInstaller @Arguments -CollisionAction Rename

    $Renamed.EntryCount | Should -Be 1
    (Get-ChildItem -LiteralPath (Join-Path $Output 'Tools') -Filter 'ToHex*').Count | Should -Be 2
  }

  It 'exports physical wrapper entries only when raw extraction is requested' {
    if (-not (Test-Path -LiteralPath $Script:MsiBootstrapper)) { Set-ItResult -Skipped -Because 'The AKInstallerMSI wrapper fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'raw-msi'
    $Result = Expand-AKInstaller -Path $Script:MsiBootstrapper -DestinationPath $Output -Name 'Config.ini_' -RawEntries -CollisionAction Error -MaximumExpandedBytes 4MB

    $Result.EntryCount | Should -Be 1
    Test-Path -LiteralPath (Join-Path $Output '_akinstaller\Config.ini_') -PathType Leaf | Should -BeTrue
  }

  It 'routes the family and emits schema-shaped exact suggestions' {
    if (-not (Test-Path -LiteralPath $Script:MsiBootstrapper)) { Set-ItResult -Skipped -Because 'The AKInstallerMSI wrapper fixture is not cached.'; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:MsiBootstrapper
    $Family = $Analysis.DetectedFamilies | Where-Object Family -CEQ 'AKInstaller' | Select-Object -First 1

    $Family | Should -Not -BeNullOrEmpty
    $Family.SuggestedManifestFields.InstallerType | Should -Be 'exe'
    $Family.SuggestedManifestFields.ProductCode | Should -Be '{87E55B71-19A8-4191-9D43-7566B969A6E9}'
    $Family.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/silent 2 /msiparam "REBOOT=ReallySuppress"'
    $Family.SuggestedManifestFields.InstallerSwitches.SilentWithProgress | Should -Be '/msilimitui 67 /msiparam "REBOOT=ReallySuppress"'
    ($Family.SuggestedManifestFields.ExpectedReturnCodes | Where-Object InstallerReturnCode -EQ 1602).ReturnResponse | Should -Be 'cancelledByUser'
    ($Family.SuggestedManifestFields.ExpectedReturnCodes | Where-Object InstallerReturnCode -EQ 3010).ReturnResponse | Should -Be 'rebootRequiredToFinish'
    ($Family.SuggestedManifestFields.ExpectedReturnCodes | Where-Object InstallerReturnCode -EQ 1641).ReturnResponse | Should -Be 'rebootInitiated'
    $Family.SuggestedManifestFields.ExpectedReturnCodes.InstallerReturnCode | Should -Not -Contain 0
    $Family.SuggestedManifestFields.ExpectedReturnCodes.InstallerReturnCode | Should -Not -Contain 1603
  }

  It 'removes modern switch and return-code defaults from classic exact suggestions' {
    if (-not (Test-Path -LiteralPath $Script:ClassicNativeInstaller)) { Set-ItResult -Skipped -Because 'The classic AKInstaller native fixture is not cached.'; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:ClassicNativeInstaller
    $Family = $Analysis.DetectedFamilies | Where-Object Family -CEQ 'AKInstaller' | Select-Object -First 1

    $Family.SuggestedManifestFields.InstallModes | Should -Be @('interactive')
    $Family.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'InstallerSwitches'
    $Family.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'ExpectedReturnCodes'
  }

  It 'duplicates the native silent switch for WinGet progress-mode fallback without claiming progress support' {
    if (-not (Test-Path -LiteralPath $Script:NativeInstaller)) { Set-ItResult -Skipped -Because 'The AKInstaller native fixture is not cached.'; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:NativeInstaller
    $Family = $Analysis.DetectedFamilies | Where-Object Family -CEQ 'AKInstaller' | Select-Object -First 1

    $Family.SuggestedManifestFields.InstallModes | Should -Be @('interactive', 'silent')
    $Family.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/silent 1 /NoReboot'
    $Family.SuggestedManifestFields.InstallerSwitches.SilentWithProgress | Should -Be '/silent 1 /NoReboot'
    ($Family.SuggestedManifestFields.ExpectedReturnCodes | Where-Object InstallerReturnCode -EQ 3010).ReturnResponse | Should -Be 'rebootRequiredToFinish'
    ($Family.SuggestedManifestFields.ExpectedReturnCodes | Where-Object InstallerReturnCode -EQ 1641).ReturnResponse | Should -Be 'rebootInitiated'
  }

  It 'does not substitute outer stub architecture when native payload analysis is unresolved' {
    if (-not (Test-Path -LiteralPath $Script:NativeInstaller)) { Set-ItResult -Skipped -Because 'The AKInstaller native fixture is not cached.'; return }
    InModuleScope AKInstaller -Parameters @{ InstallerPath = $Script:NativeInstaller } {
      Mock Get-AKInstallerNativePayloadEvidence { [pscustomobject]@{ ArchitectureInfo = $null; DependencyInfo = $null; Diagnostics = @() } }

      $Info = Get-AKInstallerInfo -Path $InstallerPath

      $Info.OuterArchitectureInfo.NativeArchitecture | Should -Be 'x86'
      $Info.PackageArchitecture | Should -BeNullOrEmpty
      $Info.SupportedArchitectures | Should -BeNullOrEmpty
      $Info.UnresolvedFields | Should -Contain 'Architecture'
    }
  }

  It 'does not replace absent classic ARP fields with compiled package identity during manifest updates' {
    if (-not (Test-Path -LiteralPath $Script:ClassicNativeInstaller)) { Set-ItResult -Skipped -Because 'The classic AKInstaller native fixture is not cached.'; return }
    InModuleScope WinGetManifestUpdate -Parameters @{ InstallerPath = $Script:ClassicNativeInstaller } {
      Mock Get-WinGetInstallerReleaseDate { $null }
      $Url = 'https://example.test/inccopy.exe'
      $Installer = [ordered]@{
        Architecture = 'x86'; InstallerType = 'exe'; Scope = 'machine'; InstallerUrl = $Url; InstallerSha256 = 'OLD'; ProductCode = 'IncCopy'
        AppsAndFeaturesEntries = @([ordered]@{ ProductCode = 'IncCopy'; DisplayName = 'IncCopy'; DisplayVersion = 'EXISTING'; Publisher = 'EXISTING' })
      }
      $OldInstaller = $Installer | Copy-Object
      $Diagnostics = [Collections.Generic.List[object]]::new()

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{ $Url = $InstallerPath }) -DiagnosticCollection $Diagnostics -Logger { param($Message, $Level) $null = $Message, $Level }

      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be 'EXISTING'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'EXISTING'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Not -Be '3.0'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Not -Be 'Andreas Kapust'
    }
  }

  It 'updates parser-owned fields while preserving context-dependent authored scope' {
    if (-not (Test-Path -LiteralPath $Script:DirectMsiBootstrapper)) { Set-ItResult -Skipped -Because 'The direct AKInstallerMSI fixture is not cached.'; return }
    InModuleScope WinGetManifestUpdate -Parameters @{ InstallerPath = $Script:DirectMsiBootstrapper } {
      Mock Get-WinGetInstallerReleaseDate { $null }
      $Url = 'https://example.test/regipay.exe'
      $Installer = [ordered]@{
        Architecture = 'x86'; InstallerType = 'exe'; Scope = 'user'; InstallerUrl = $Url; InstallerSha256 = 'OLD'
        ProductCode = '{OLD-PRODUCT}'; ReleaseDate = '2026-01-01'
        AppsAndFeaturesEntries = @([ordered]@{ ProductCode = '{OLD-PRODUCT}'; UpgradeCode = '{OLD-UPGRADE}'; InstallerType = 'msi' })
      }
      $OldInstaller = $Installer | Copy-Object
      $Diagnostics = [Collections.Generic.List[object]]::new()

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{ $Url = $InstallerPath }) -DiagnosticCollection $Diagnostics -Logger { param($Message, $Level) $null = $Message, $Level }

      $Result.ProductCode | Should -Be '{012D2F85-C9DC-4DCB-BD16-DDBA17BD6209}'
      $Result.Scope | Should -Be 'user'
      $Result.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{3A11F797-CAD6-43B8-886F-20ADD5CABAE3}'
      $Diagnostics.Id | Should -Contain 'AKInstallerMSI.Scope.ContextDependent'
    }
  }
}
