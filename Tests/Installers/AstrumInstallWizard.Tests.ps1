. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force

  $Script:AstrumProbe = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\2.29.50\ProbeNormal\ProbeNormal.exe'
  $Script:AstrumTiny = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\2.29.50\ProbeTiny.exe'
  $Script:AstrumTinyVerbose = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\2.29.50\ProbeTinyVerbose.exe'
  $Script:AstrumLegacyTiny = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\1.95.5\LegacyTiny.exe'
  $Script:AstrumLegacyTinyVerbose = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\1.95.5\LegacyTinyVerbose.exe'
  $Script:AstrumSpannedDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\2.29.50\ProbeSpanned'
  $Script:AstrumSpanned = Join-Path $Script:AstrumSpannedDirectory 'ProbeSpanned.exe'
  $Script:AstrumVolumes = @(Get-ChildItem -LiteralPath $Script:AstrumSpannedDirectory -Filter 'ProbeSpanned.0*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -ExpandProperty FullName)
  $Script:AstrumBuilder = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\AstrumInstallWizard\Thraex.AstrumInstallWizard\2.29.50\setup.exe'
  $Script:AstrumLegacy180 = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\AstrumInstallWizard\Thraex.AstrumInstallWizard\1.80\setup.exe'
  $Script:AstrumLegacy1955 = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\AstrumInstallWizard\Thraex.AstrumInstallWizard\1.95.5\setup.exe'
  $Script:AstrumEarly20150 = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\AstrumInstallWizard\Thraex.AstrumInstallWizard\2.01.50\setup.exe'
  $Script:AstrumModern22120 = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\AstrumInstallWizard\Thraex.AstrumInstallWizard\2.21.20\setup.exe'
  $Script:BreakAlube = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\AstrumInstallWizard\GroeneveldBeka.BreakAlubePCGINA\1.0.1.5\setup.exe'
  $Script:IconicoScreenMeasurementPack = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\AstrumInstallWizard\Iconico.ScreenMeasurementPack\2025-02-18\ScreenMeasurementPack.zip'
  $Script:AstrumVariants = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\2.29.50\Variants'
  $Script:AstrumResourceFile = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AstrumInstallWizard\2.29.50\Variants\ResourceFile\ResourceFile.exe'
}

Describe 'Astrum InstallWizard structural detection' {
  It 'loads complete generation and configuration descriptors from the format catalog' {
    InModuleScope AstrumInstallWizard {
      $Script:AstrumFormatCatalog.CatalogVersion | Should -Be 1
      @($Script:AstrumFormatsByFooterLength.Values).Count | Should -Be 2
      $Script:AstrumOperationSemantics.TextActions[1] | Should -Be 'Add to end of file'
      $Script:AstrumOperationSemantics.FileActions[1] | Should -Be 'Delete'
      $Script:AstrumOperationSemantics.InteractiveActions[1] | Should -Be 'Open document'
      $Script:AstrumOperationSemantics.InteractiveActions[6] | Should -Be 'Execute program and wait'
      $Script:AstrumOperationSemantics.InteractiveActions[9] | Should -Be 'Assign variable value'
      $Script:AstrumOperationSemantics.Timings[13] | Should -Be 'On shutdown'
      $Script:AstrumOperationSemantics.ConditionOperators[3] | Should -Be 'Less than'
      $Script:AstrumOperationSemantics.ConditionOperators[6] | Should -Be 'Contains / Binary and'
      $Script:AstrumVariableSemantics.Types | Should -Be @('Text', 'Number')
      $Script:AstrumVariableSemantics.Sources['0'] | Should -Be 'Registry'
      $Script:AstrumVariableSemantics.Sources['4294967295'] | Should -Be 'Nowhere'
      @($Script:AstrumFormatsByGeneration.Keys | Sort-Object) | Should -Be @('1.x', '2.x')

      foreach ($Format in $Script:AstrumFormatsByFooterLength.Values) {
        $Format.Id | Should -Not -BeNullOrEmpty
        $Format.FileDescriptorSize % 4 | Should -Be 0
        @($Format.ValidationInvariants).Count | Should -BeGreaterThan 0
        foreach ($Name in 'ConfigurationOffset', 'ConfigurationSize', 'UninstallerCompressedSize', 'UninstallerOffset', 'InstallationItemCount', 'InstallationItemOffset', 'InstallationItemSize', 'FileCount', 'FileOffset', 'PayloadSize', 'ExpandedSize', 'InstalledSize', 'SelfPointer') {
          $Format.FooterOffsets.ContainsKey($Name) | Should -BeTrue
          [int]$Format.FooterOffsets[$Name] | Should -BeLessThan $Format.FooterLength
        }
        $Script:AstrumConfigurationProfiles.ContainsKey([string]$Format.DefaultConfigurationProfile) | Should -BeTrue
        if ($Format.RuntimeWordProfile) { $Script:AstrumConfigurationProfiles.ContainsKey([string]$Format.RuntimeWordProfile) | Should -BeTrue }
      }

      $Modern = $Script:AstrumConfigurationProfiles.Modern2
      $Script:AstrumConfigurationProfiles.Legacy1.ObservedVersionRange | Should -Be '1.80-1.95.5'
      $Script:AstrumConfigurationProfiles.Early2.ObservedVersionRange | Should -Be '2.01.50-2.04.20'
      $Modern.ObservedVersionRange | Should -Be '2.21.20-2.29.50'
      @($Modern.OptionFields.Name | Sort-Object -Unique).Count | Should -Be @($Modern.OptionFields).Count
      $Modern.OptionFields.Name | Should -Contain 'MinimumCpuSpeedMHz'
      $Modern.OptionFields.Name | Should -Contain 'MinimumJavaVersion'
      $Modern.OptionFields.Name | Should -Contain 'RequireAdmin'
      $Modern.OptionFields.Name | Should -Contain 'ProhibitSilentInstallation'
      @($Modern.OptionFields | Where-Object Origin -EQ 'AfterJavaVersion').Count | Should -BeGreaterThan 0
    }
  }

  It 'requires the complete footer, protected configuration, and bounded catalog' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    Test-AstrumInstallWizard -Path $Script:AstrumProbe | Should -BeTrue

    $MarkerOnly = Join-Path $TestDrive 'marker-only.exe'
    Copy-Item -LiteralPath (Get-Process -Id $PID).Path -Destination $MarkerOnly
    $Stream = [IO.File]::Open($MarkerOnly, 'Append', 'Write', 'Read')
    try {
      $Bytes = [Text.Encoding]::ASCII.GetBytes('Astrum InstallWizard Thraex Software') + [byte[]](0x3E, 0x2D, 0x1C, 0x0B, 0x78, 0x56, 0x34, 0x12)
      $Stream.Write($Bytes, 0, $Bytes.Length)
    } finally { $Stream.Dispose() }
    Test-AstrumInstallWizard -Path $MarkerOnly | Should -BeFalse
  }

  It 'rejects a truncated catalog deterministically' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    $Truncated = Join-Path $TestDrive 'truncated.exe'
    Copy-Item -LiteralPath $Script:AstrumProbe -Destination $Truncated
    $Stream = [IO.File]::Open($Truncated, 'Open', 'ReadWrite', 'Read')
    try { $Stream.SetLength($Stream.Length - 24) } finally { $Stream.Dispose() }
    Test-AstrumInstallWizard -Path $Truncated | Should -BeFalse
    { Get-AstrumInstallWizardInfo -Path $Truncated } | Should -Throw
  }

  It 'unwraps silent and verbose tiny media through their bound GZip ranges' {
    if (-not (Test-Path -LiteralPath $Script:AstrumTiny) -or -not (Test-Path -LiteralPath $Script:AstrumTinyVerbose)) { Set-ItResult -Skipped -Because 'The controlled Astrum tiny fixtures are not cached.'; return }
    (Get-AstrumInstallWizardInfo -Path $Script:AstrumTiny).ContainerRoute | Should -Be 'Astrum2/Tiny'
    (Get-AstrumInstallWizardInfo -Path $Script:AstrumTinyVerbose).ContainerRoute | Should -Be 'Astrum2/TinyVerbose'
    Test-AstrumInstallWizard -Path $Script:AstrumTiny | Should -BeTrue
    Test-AstrumInstallWizard -Path $Script:AstrumTinyVerbose | Should -BeTrue
  }

  It 'unwraps legacy 1.x silent and verbose tiny media through the same validated descriptor route' {
    if (-not (Test-Path -LiteralPath $Script:AstrumLegacyTiny) -or -not (Test-Path -LiteralPath $Script:AstrumLegacyTinyVerbose)) { Set-ItResult -Skipped -Because 'The controlled legacy Astrum tiny fixtures are not cached.'; return }
    (Get-FileHash -LiteralPath $Script:AstrumLegacyTiny -Algorithm SHA256).Hash | Should -Be 'C946D74CA1FB684AFCC95B37718F9D1E87F3712CB34DE8CC9F1215B9C89A039B'
    (Get-FileHash -LiteralPath $Script:AstrumLegacyTinyVerbose -Algorithm SHA256).Hash | Should -Be '13AF2019ACF4C8F3155E145A89305CF87D0FEB9FD5B40A10CF4317823B486F13'
    (Get-AstrumInstallWizardInfo -Path $Script:AstrumLegacyTiny).ContainerRoute | Should -Be 'Astrum1/Tiny'
    (Get-AstrumInstallWizardInfo -Path $Script:AstrumLegacyTinyVerbose).ContainerRoute | Should -Be 'Astrum1/TinyVerbose'
    Test-AstrumInstallWizard -Path $Script:AstrumLegacyTiny | Should -BeTrue
    Test-AstrumInstallWizard -Path $Script:AstrumLegacyTinyVerbose | Should -BeTrue
  }

  It 'locates the logical Astrum trailer before a PE certificate table' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    $Signed = Join-Path $TestDrive 'signed-envelope.exe'
    $Bytes = [IO.File]::ReadAllBytes($Script:AstrumProbe)
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
    [IO.File]::WriteAllBytes($Signed, $Output)

    Test-AstrumInstallWizard -Path $Signed | Should -BeTrue
    (Get-AstrumInstallWizardInfo -Path $Signed).ContainerRoute | Should -Be 'Astrum2/SignedSingleFile'
  }

  It 'dispatches historical 1.x and 2.x trailer, configuration, and catalog profiles' {
    $Cases = @(
      @{ Path = $Script:AstrumLegacy180; Hash = '71D6C6361D2B069E7B28AC9B460FD47A4AF71C07A5A82D2B0349623D9F0636A0'; Format = 'astrum-1'; Generation = '1.x'; Profile = 'Legacy1'; Route = 'Astrum1/LegacySingleFile'; Version = '1.80'; Files = 148; HasMagic = $false },
      @{ Path = $Script:AstrumLegacy1955; Hash = '1245412FFA57761A988D7881062ACE262EB9C9F2BA028F55544CDB24423C6F7C'; Format = 'astrum-1'; Generation = '1.x'; Profile = 'Legacy1'; Route = 'Astrum1/SingleFile'; Version = '1.95.5'; Files = 209; HasMagic = $true },
      @{ Path = $Script:AstrumEarly20150; Hash = 'DA0D51CE828C3AC56248725E4130D641F306921AF850E8522340928A4B1F3EB6'; Format = 'astrum-2'; Generation = '2.x'; Profile = 'Early2'; Route = 'Astrum2/SingleFile'; Version = '2.01.50'; Files = 157; HasMagic = $true },
      @{ Path = $Script:AstrumModern22120; Hash = 'E03460739CD74A76C23038B5DA33074E3FF0D436E729D8ADEE4C27DE53C91FA1'; Format = 'astrum-2'; Generation = '2.x'; Profile = 'Modern2'; Route = 'Astrum2/SignedSingleFile'; Version = '2.21.20'; Files = 123; HasMagic = $true }
    )
    if ($Cases.Path | Where-Object { -not (Test-Path -LiteralPath $_) }) { Set-ItResult -Skipped -Because 'The historical Astrum fixtures are not cached.'; return }

    foreach ($Case in $Cases) {
      (Get-FileHash -LiteralPath $Case.Path -Algorithm SHA256).Hash | Should -Be $Case.Hash
      $Info = Get-AstrumInstallWizardInfo -Path $Case.Path
      $Info.FormatCatalogId | Should -Be $Case.Format
      $Info.FormatGeneration | Should -Be $Case.Generation
      $Info.ConfigurationProfile | Should -Be $Case.Profile
      $Info.ContainerRoute | Should -Be $Case.Route
      $Info.DisplayVersion | Should -Be $Case.Version
      $Info.PayloadCatalog.Count | Should -Be $Case.Files
      $Info.Trailer.HasMagic | Should -Be $Case.HasMagic
      $Info.ParserVersionInfo.CatalogVersion | Should -Be 1
      $Info.ParserVersionInfo.ConfigurationProfileObservedVersionRange | Should -Not -BeNullOrEmpty
    }

    $LegacyInfo = Get-AstrumInstallWizardInfo -Path $Script:AstrumLegacy180
    $LegacyInfo.SupportsSilentInstallation | Should -BeTrue
    $LegacyInfo.InstallerSwitches.Silent | Should -Be '/silent'
    $LegacyInfo.InstallerSwitches.SilentWithProgress | Should -Be '/silent'
    $LegacyInfo.InstallModes | Should -Be @('interactive', 'silent')
    $LegacyInfo.InstallerSuccessCodes | Should -BeNullOrEmpty
    $LegacyInfo.RuntimeCommandLineEvidence.Switches | Should -Contain '/silent'
    $LegacyInfo.RuntimeCommandLineEvidence.Offsets.'/silent' | Should -BeGreaterThan 0
    $LegacyRecords = @($LegacyInfo.Shortcuts) + @($LegacyInfo.IniOperations) + @($LegacyInfo.TextOperations) + @($LegacyInfo.FileOperations) + @($LegacyInfo.InteractiveOperations)
    $LegacyRecords.Count | Should -BeGreaterThan 0
    @($LegacyRecords.ObservedOperationTail | Sort-Object -Unique) | Should -Be @(0)
    @($LegacyRecords.Condition | Where-Object { $_ }).Count | Should -Be 0
    $LegacyInfo.Diagnostics.Id | Should -Not -Contain 'Astrum.Silent.LegacyRuntimeVersionRequired'
    $VersionedRuntime = $LegacyInfo.PayloadCatalog | Where-Object Path -Like '*Astrum InstallWizard.exe'
    $VersionedRuntime.VersionResourceEvidence.FileVersion | Should -Be '1.8.0.0'
    $VersionedRuntime.VersionResourceEvidence.CodePage | Should -Be 1252

    $Early2Info = Get-AstrumInstallWizardInfo -Path $Script:AstrumEarly20150
    $Early2Info.Configuration.ApplicationName | Should -Be 'Astrum InstallWizard 2'
    $Early2Info.Configuration.CompanyName | Should -Be 'Thraex Software'
    $Early2Info.Configuration.InstallPath | Should -Be '<ProgramFiles>\Astrum InstallWizard 2'
    $Early2Info.InstallerSwitches.Silent | Should -Be '/silent'
    $Early2Info.InstallerSuccessCodes | Should -Be @(1)
    ($Early2Info.Variables | Where-Object Name -EQ '<DesktopShortcut>').SourceName | Should -Be 'Nowhere'
    $UserHomeVariable = $Early2Info.Variables | Where-Object Name -EQ '<UserHome>'
    $UserHomeVariable.TypeName | Should -Be 'Text'
    $UserHomeVariable.SourceName | Should -Be 'Registry'
    $UserHomeVariable.Location1 | Should -Be '-2147483647'
  }

  It 'dispatches mixed Astrum generations from the Iconico measurement bundle' {
    if (-not (Test-Path -LiteralPath $Script:IconicoScreenMeasurementPack)) { Set-ItResult -Skipped -Because 'The Iconico Astrum fixture is not cached.'; return }
    (Get-DumplingsTestFixtureHash -Path $Script:IconicoScreenMeasurementPack) | Should -Be '18DAE7C323F391A4B4F092BE7B6990561727E225B9124E476BAFB693CCD340BF'

    $Cases = @(
      @{ Entry = 'Caliper.exe'; Hash = 'DD2BA4F1C3AE8E2AE2C6AE01AE3F3C5260633EAF00C8BB4F95F51CA618BB8877'; Format = 'astrum-1'; Generation = '1.x'; Profile = 'Legacy1'; Route = 'Astrum1/SingleFile'; Name = 'Screen Calipers'; Version = '4.0'; Items = 3; Files = 56; Compression = @('GZip', 'Stored') },
      @{ Entry = 'ColorPic.exe'; Hash = '1DE5CC14A08B240FEF37FEC3D7E6B70819F24D9CEB60E6F827CBDFBAEC985FB7'; Format = 'astrum-2'; Generation = '2.x'; Profile = 'Modern2'; Route = 'Astrum2/SignedSingleFile'; Name = 'ColorPic'; Version = '5.1'; Items = 1; Files = 6; Compression = @('GZip') }
    )
    $Archive = [IO.Compression.ZipFile]::OpenRead($Script:IconicoScreenMeasurementPack)
    try {
      foreach ($Case in $Cases) {
        $Entry = $Archive.GetEntry($Case.Entry)
        $Entry | Should -Not -BeNullOrEmpty
        $InstallerPath = Join-Path $TestDrive $Case.Entry
        $ArchiveInput = $Entry.Open()
        $Output = [IO.File]::Create($InstallerPath)
        try { $ArchiveInput.CopyTo($Output) } finally { $Output.Dispose(); $ArchiveInput.Dispose() }

        (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash | Should -Be $Case.Hash
        $Info = Get-AstrumInstallWizardInfo -Path $InstallerPath
        $Info.FormatCatalogId | Should -Be $Case.Format
        $Info.FormatGeneration | Should -Be $Case.Generation
        $Info.ConfigurationProfile | Should -Be $Case.Profile
        $Info.ContainerRoute | Should -Be $Case.Route
        $Info.DisplayName | Should -Be $Case.Name
        $Info.DisplayVersion | Should -Be $Case.Version
        $Info.Scope | Should -Be 'machine'
        @($Info.InstallationItems).Count | Should -Be $Case.Items
        @($Info.PayloadCatalog).Count | Should -Be $Case.Files
        @($Info.CompressionEvidence.Algorithm | Sort-Object -Unique) | Should -Be $Case.Compression
        if ($Case.Entry -eq 'Caliper.exe') {
          # The 1.x interactive-action record ends after ExecuteCount. These checks prevent the
          # following application identity from being consumed as nonexistent 2.x tail fields.
          $Info.Configuration.ApplicationName | Should -Be 'Screen Calipers'
          $Info.Configuration.CompanyName | Should -Be 'Iconico'
          $Info.Configuration.InstallPath | Should -Be '<ProgramFiles>\Screen Calipers 4.0'
          @($Info.InteractiveOperations).Count | Should -Be 1
          $Info.InteractiveOperations[0].Flags | Should -BeNullOrEmpty
          $Info.InteractiveOperations[0].CustomMessage | Should -BeNullOrEmpty
          $Info.InteractiveOperations[0].Condition | Should -BeNullOrEmpty
          $Info.InteractiveOperations[0].ObservedOperationTail | Should -BeNullOrEmpty
        }
      }
    } finally {
      $Archive.Dispose()
    }
  }

  It 'requires complete explicitly ordered companion volumes for spanned media' {
    if (-not (Test-Path -LiteralPath $Script:AstrumSpanned) -or $Script:AstrumVolumes.Count -ne 4) { Set-ItResult -Skipped -Because 'The controlled Astrum spanned fixture is not cached.'; return }
    Test-AstrumInstallWizard -Path $Script:AstrumSpanned | Should -BeFalse
    Test-AstrumInstallWizard -Path $Script:AstrumSpanned -CompanionFile $Script:AstrumVolumes | Should -BeTrue
    { Get-AstrumInstallWizardInfo -Path $Script:AstrumSpanned -CompanionFile $Script:AstrumVolumes[0..2] } | Should -Throw '*catalog requires*'
    $Info = Get-AstrumInstallWizardInfo -Path $Script:AstrumSpanned -CompanionFile $Script:AstrumVolumes
    $Info.ContainerRoute | Should -Be 'Astrum2/Spanned'
    Read-ProductNameFromAstrumInstallWizard -Path $Script:AstrumSpanned -CompanionFile $Script:AstrumVolumes | Should -Be 'Dumplings ARP Probe'
    $Info.PayloadCatalog[0].VolumeOffsets.Count | Should -Be 5
    $Info.PayloadCatalog[0].ExpectedSize | Should -Be 2097152
  }
}

Describe 'Astrum InstallWizard metadata and ARP evidence' {
  It 'parses a controlled project with independent application and ARP identities' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    $Info = Get-AstrumInstallWizardInfo -Path $Script:AstrumProbe

    $Info.Family | Should -Be 'Astrum InstallWizard'
    $Info.FormatGeneration | Should -Be '2.x'
    $Info.DisplayName | Should -Be 'Dumplings ARP Probe'
    $Info.DisplayVersion | Should -Be '77.88.99'
    $Info.Publisher | Should -Be 'Dumplings ARP Publisher'
    $Info.ProductCode | Should -Be 'Dumplings Astrum Probe'
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.ElevationRequirement | Should -Be 'elevationRequired'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Dumplings Astrum Probe'
    $Info.UninstallString | Should -Be '"%ProgramFiles(x86)%\Dumplings Astrum Probe\Odd Uninstaller.exe"'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.ArpEntries.Count | Should -Be 1
    $Info.ArpEntries[0].Root | Should -Be 'HKLM'
    $Info.ArpEntries[0].InstallLocation | Should -BeNullOrEmpty
    $Info.ArpEntries[0].DisplayIcon | Should -BeNullOrEmpty
    $Info.InstallerSwitches.Silent | Should -Be '/silent'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/silent'
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.InstallerSuccessCodes | Should -Be @(1)
    $Info.PayloadCatalog.Path | Should -Contain '<InstallDir>\Data\Alpha.txt'
    $Info.PayloadCatalog.Compression | Should -Contain 'Stored'
    $Info.Footer.UninstallerCompressedSize | Should -BeGreaterThan 0
    $Info.Diagnostics.Id | Should -Not -Contain 'Astrum.Configuration.PartialTail'
    $Info.Configuration.OptionBlockSize | Should -Be 355
    $Info.Configuration.OptionBlockEvidence.AssignedByteCount | Should -Be 95
    $Info.Configuration.OptionBlockEvidence.UnassignedRanges.Count | Should -BeGreaterThan 0
    @($Info.Diagnostics | Where-Object { $null -ne $_.Level }).Count | Should -Be 0
    $Info.UnresolvedFields | Should -BeNullOrEmpty
  }

  It 'parses the Astrum builder installer as a real 2.x regression' {
    if (-not (Test-Path -LiteralPath $Script:AstrumBuilder)) { Set-ItResult -Skipped -Because 'The supplied Astrum builder installer is not cached.'; return }
    (Get-FileHash -LiteralPath $Script:AstrumBuilder -Algorithm SHA256).Hash | Should -Be '657A8F9CC933A5E11378F65378FE55347A45781948D300A12FE0FD41256C2F8A'
    $Info = Get-AstrumInstallWizardInfo -Path $Script:AstrumBuilder
    $Info.DisplayName | Should -Be 'Astrum InstallWizard 2'
    $Info.DisplayVersion | Should -Be '2.29.50'
    $Info.Publisher | Should -Match 'Thraex'
    $Info.PayloadCatalog.Count | Should -Be 124
    $Info.InstallationItems.Count | Should -Be 2
    $Info.Shortcuts.Count | Should -Be 5
    $Info.FileOperations.Count | Should -Be 4
    $Info.TextOperations[0].OperationName | Should -Be 'Add to end of file'
    $Info.FileOperations[0].ActionName | Should -Be 'Delete'
    $Info.FileOperations[0].TimingName | Should -Be 'After installation'
    $Info.InteractiveOperations.Count | Should -Be 2
    $Info.InteractiveOperations[0].ActionName | Should -Be 'Assign variable value'
    $Info.InteractiveOperations[0].TimingName | Should -Be 'At program startup'
    $Info.InteractiveOperations[1].ActionName | Should -Be 'Execute program'
    $Info.InteractiveOperations[1].TimingName | Should -Be 'On shutdown'
    $Info.InteractiveOperations[1].Condition.OperatingSystemMask | Should -Be 1
    $Info.InteractiveOperations[1].Condition.Terms[0].OperatorName | Should -Be 'Equals'
    $Info.InteractiveOperations[1].Condition.Terms[1].OperatorName | Should -Be 'Less than'
    $Info.ExecutedPayloads.Count | Should -Be 1
    $Info.ExecutedPayloads[0].File | Should -Be '<InstallDir>\converter.exe'
    $DesktopShortcutVariable = $Info.Variables | Where-Object Name -EQ '<DesktopShortcut>'
    $DesktopShortcutVariable.TypeName | Should -Be 'Number'
    $DesktopShortcutVariable.SourceName | Should -Be 'Nowhere'
    $DesktopShortcutVariable.DefaultValue | Should -Be '0'
    $VersionVariable = $Info.Variables | Where-Object Name -EQ '<Version1Installed>'
    $VersionVariable.SourceName | Should -Be 'Registry'
    $VersionVariable.SetTrueIfExists | Should -BeTrue
    $Info.Diagnostics.Id | Should -Not -Contain 'Astrum.Variable.UnknownCode'
    $Info.FileExtensions | Should -Contain 'ai2'
    $Info.FileExtensions | Should -Contain 'adt'
  }

  It 'resolves BreakAlube variables whose compiled source has a deterministic default' {
    if (-not (Test-Path -LiteralPath $Script:BreakAlube)) { Set-ItResult -Skipped -Because 'The supplied BreakAlube installer is not cached.'; return }
    (Get-FileHash -LiteralPath $Script:BreakAlube -Algorithm SHA256).Hash | Should -Be '9024FD2F27A0B2192B44A00A66FB2BFA37E5309DA3645194E9FC6F1D1E158600'
    $Info = Get-AstrumInstallWizardInfo -Path $Script:BreakAlube
    $Info.DisplayName | Should -Be 'PC-GINA V1.0.1.5BreakAlube, PC-GINA, '
    $Info.ProductCode | Should -Be 'PC-GINA V1.0.1.5'
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.PayloadCatalog.Count | Should -Be 5
    $Info.InstallationItems.Name | Should -Contain 'driver'
    $Info.ArpEntries[0].DisplayName | Should -Be 'PC-GINA V1.0.1.5BreakAlube, PC-GINA, '
    $Info.ArpEntries[0].Root | Should -Be 'HKLM'
    $Info.ArpEntries[0].InstallLocation | Should -BeNullOrEmpty
    $Info.ArpEntries[0].UninstallString | Should -Be '"%WINDIR%\BreakAlube, PC-GINA, 1.0.1.5 Uninstaller.exe"'
    $Info.ArpEntries[0].DisplayIcon | Should -Be '%ProgramFiles(x86)%\Groeneveld Software\BreakAlube, PC-GINA, V1.0.1.5\driver\Groeneveld icon.ico'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Groeneveld Software\BreakAlube, PC-GINA, V1.0.1.5'
    $Info.DisplayIcon | Should -Be '%ProgramFiles(x86)%\Groeneveld Software\BreakAlube, PC-GINA, V1.0.1.5\driver\Groeneveld icon.ico'
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'PC-GINA V1.0.1.5BreakAlube, PC-GINA, '
    $Info.Diagnostics.Id | Should -Not -Contain 'Astrum.Arp.Unresolved.DisplayName'
    $Info.Diagnostics.Id | Should -Not -Contain 'Astrum.Arp.Unresolved.UninstallString'
    $Info.Diagnostics.Id | Should -Not -Contain 'Astrum.Arp.Unresolved.DisplayIcon'
    $Info.UnresolvedFields | Should -Be @()
    $Info.DisplayVersion | Should -Be '1.0.1.5'
    $Info.InteractiveOperations[0].ActionCode | Should -Be 6
    $Info.InteractiveOperations[0].ActionName | Should -Be 'Execute program and wait'
    $Info.ExecutedPayloads.Count | Should -Be 1
    $Info.ExecutedPayloads[0].File | Should -Be '<InstallDir>\driver\CDM20802_Setup.exe'
    ($Info.Variables | Where-Object Name -EQ '<TimerName>').SourceName | Should -Be 'Nowhere'
    $MainPathVariable = $Info.Variables | Where-Object Name -EQ '<MainPath>'
    $MainPathVariable.SourceName | Should -Be 'Registry'
    $MainPathVariable.Location1 | Should -Be '-2147483648'
  }

  It 'resolves only static custom-variable defaults and bounds recursive substitution' {
    InModuleScope AstrumInstallWizard {
      $Configuration = [pscustomobject]@{
        ApplicationName = 'App'; ApplicationVersion = '1'; CompanyName = 'Publisher'; UninstallerName = 'Uninstall.exe'
        Variables = @(
          [pscustomobject]@{ Name = '<Literal>'; DefaultValue = '<Nested>'; SourceCode = [uint32]::MaxValue; Location1 = ''; Location2 = ''; Location3 = '' },
          [pscustomobject]@{ Name = '<Nested>'; DefaultValue = 'Resolved'; SourceCode = [uint32]::MaxValue; Location1 = ''; Location2 = ''; Location3 = '' },
          [pscustomobject]@{ Name = '<Dynamic>'; DefaultValue = 'Fallback'; SourceCode = 0; Location1 = '-2147483646'; Location2 = 'Software\Vendor'; Location3 = 'Value' },
          [pscustomobject]@{ Name = '<CycleA>'; DefaultValue = '<CycleB>'; SourceCode = [uint32]::MaxValue; Location1 = ''; Location2 = ''; Location3 = '' },
          [pscustomobject]@{ Name = '<CycleB>'; DefaultValue = '<CycleA>'; SourceCode = [uint32]::MaxValue; Location1 = ''; Location2 = ''; Location3 = '' }
        )
      }

      Resolve-AstrumVariables -Value '<Literal>' -Configuration $Configuration -InstallLocation '%ProgramFiles%\App' | Should -Be 'Resolved'
      Resolve-AstrumVariables -Value '<Dynamic>' -Configuration $Configuration -InstallLocation '%ProgramFiles%\App' | Should -Be '<Dynamic>'
      Resolve-AstrumVariables -Value '<CycleA>' -Configuration $Configuration -InstallLocation '%ProgramFiles%\App' | Should -Match '^<Cycle[AB]>$'
    }
  }

  It 'keeps unresolved ARP identity out of WinGet-facing entries' {
    InModuleScope AstrumInstallWizard {
      $Entry = [pscustomobject]@{
        ProductCode    = '<DynamicKey>'
        DisplayName    = 'Known display name'
        DisplayVersion = '<DynamicVersion>'
        Publisher      = '<DynamicPublisher>'
      }

      $Projected = ConvertTo-AstrumAppsAndFeaturesEntry -Entry $Entry
      $Projected.DisplayName | Should -Be 'Known display name'
      $Projected.PSObject.Properties.Name | Should -Not -Contain 'ProductCode'
      $Projected.PSObject.Properties.Name | Should -Not -Contain 'DisplayVersion'
      $Projected.PSObject.Properties.Name | Should -Not -Contain 'Publisher'
    }
  }


  It 'derives silent and license behavior from compiled options and dialog resources' {
    $LicenseRequired = Join-Path $Script:AstrumVariants 'LicenseRequired.exe'
    $UserInformation = Join-Path $Script:AstrumVariants 'UserInfoDialog.exe'
    if (-not (Test-Path -LiteralPath $LicenseRequired) -or -not (Test-Path -LiteralPath $UserInformation)) { Set-ItResult -Skipped -Because 'The controlled Astrum policy fixtures are not cached.'; return }

    $LicenseInfo = Get-AstrumInstallWizardInfo -Path $LicenseRequired
    $LicenseInfo.LicenseDialogSelected | Should -BeTrue
    $LicenseInfo.LicenseAcceptanceRequired | Should -BeTrue
    $LicenseInfo.InstallerSwitches.Silent | Should -Be '/silent'
    $LicenseInfo.InstallerSwitches.Custom | Should -Be '/AcceptLicense'
    $LicenseInfo.Diagnostics.Id | Should -Contain 'Astrum.Silent.LicenseAcceptance'

    $UserInfo = Get-AstrumInstallWizardInfo -Path $UserInformation
    $UserInfo.UserInformationBlocksSilent | Should -BeFalse
    $UserInfo.SupportsSilentInstallation | Should -BeTrue
    $UserInfo.InstallModes | Should -Be @('interactive', 'silent')
    $UserInfo.InstallerSwitches.Silent | Should -Be '/silent'
    $UserInfo.Diagnostics.Id | Should -Contain 'Astrum.Silent.UserInformationDialogIgnored'
  }

  It 'decodes x64 registry, uninstaller, elevation, and requirement options' {
    $Required = @('X64Mode.exe', 'NoUninstall.exe', 'RequireAdmin.exe', 'Requirements.exe', 'HiddenArp.exe', 'AsInvoker.exe') | ForEach-Object { Join-Path $Script:AstrumVariants $_ }
    if ($Required | Where-Object { -not (Test-Path -LiteralPath $_) }) { Set-ItResult -Skipped -Because 'The controlled Astrum option fixtures are not cached.'; return }

    (Get-AstrumInstallWizardInfo -Path $Required[0]).RegistryView | Should -Be '64-bit'
    $NoUninstall = Get-AstrumInstallWizardInfo -Path $Required[1]
    $NoUninstall.NoUninstallation | Should -BeTrue
    $NoUninstall.Footer.UninstallerCompressedSize | Should -Be 0
    $NoUninstall.Diagnostics.Id | Should -Contain 'Astrum.Uninstall.Disabled'
    (Get-AstrumInstallWizardInfo -Path $Required[2]).ElevationRequirement | Should -Be 'elevationRequired'

    $Requirements = (Get-AstrumInstallWizardInfo -Path $Required[3]).Requirements
    $Requirements.MinimumCpuSpeedMHz | Should -Be 4000
    $Requirements.MinimumMemoryMiB | Should -Be 4096
    $Requirements.MinimumDirectXMajor | Should -Be 10
    $Requirements.MinimumDirectXMinor | Should -Be 9
    $Requirements.MinimumResolutionWidth | Should -Be 1920
    $Requirements.MinimumResolutionHeight | Should -Be 1080
    $Requirements.RequiresWavePlayback | Should -BeTrue
    $Requirements.RequiresMidiPlayback | Should -BeTrue
    $Requirements.RequiresJoystick | Should -BeTrue

    $HiddenArp = Get-AstrumInstallWizardInfo -Path $Required[4]
    $HiddenArp.WritesAppsAndFeaturesEntry | Should -BeFalse
    $HiddenArp.ProductCode | Should -BeNullOrEmpty
    $HiddenArp.Scope | Should -Be 'machine'
    $HiddenArp.AppsAndFeaturesEntries | Should -BeNullOrEmpty

    $AsInvoker = Get-AstrumInstallWizardInfo -Path $Required[5]
    $AsInvoker.RequestedExecutionLevel | Should -Be 'asInvoker'
    $AsInvoker.Scope | Should -Be 'machine'
    $AsInvoker.ElevationRequirement | Should -Be 'elevationRequired'
    $AsInvoker.Diagnostics.Id | Should -Contain 'Astrum.Elevation.CallerRequired'
  }

  It 'decodes Windows, Java, .NET, and display requirements without shifting later options' {
    $RequirementIndexes = Join-Path $Script:AstrumVariants 'RequirementIndexes.exe'
    $JavaRequireAdmin = Join-Path $Script:AstrumVariants 'JavaRequireAdmin.exe'
    if (-not (Test-Path -LiteralPath $RequirementIndexes) -or -not (Test-Path -LiteralPath $JavaRequireAdmin)) { Set-ItResult -Skipped -Because 'The controlled Astrum variable-length requirement fixtures are not cached.'; return }

    (Get-FileHash -LiteralPath $RequirementIndexes -Algorithm SHA256).Hash | Should -Be 'EC2BED2B244AEA703FC7262C2324C73911E9277F78C2A28C61B3666C507B9F3A'
    $Requirements = (Get-AstrumInstallWizardInfo -Path $RequirementIndexes).Requirements
    $Requirements.WindowsPlatformMask | Should -Be 6
    $Requirements.MinimumWindows9xVersion | Should -Be 'Windows 98'
    $Requirements.MinimumWindowsNtVersion | Should -Be 'Windows Server 2003'
    $Requirements.MinimumResolutionBitsPerPixel | Should -Be 32
    $Requirements.MinimumDotNetFramework | Should -Be '4.0 Client'
    $Requirements.MinimumJavaVersion | Should -Be '1.4.2'

    $JavaInfo = Get-AstrumInstallWizardInfo -Path $JavaRequireAdmin
    $JavaInfo.Requirements.MinimumJavaVersion | Should -Be '1.4.2'
    $JavaInfo.RequireAdmin | Should -BeTrue
    $JavaInfo.ElevationRequirement | Should -Be 'elevationRequired'
  }
}

Describe 'Astrum InstallWizard extraction' {
  It 'streams installed files and the configured generated uninstaller' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'expanded'
    $Files = @(Expand-AstrumInstallWizard -Path $Script:AstrumProbe -DestinationPath $Output -CollisionAction Error)

    $Files.Count | Should -Be 2
    (Get-Content -LiteralPath (Join-Path $Output 'Data\Alpha.txt') -Raw).TrimEnd("`r", "`n") | Should -Be 'ASTRUM-PAYLOAD-ALPHA-0123456789'
    Test-Path -LiteralPath (Join-Path $Output 'Odd Uninstaller.exe') | Should -BeTrue
    (Get-Item -LiteralPath (Join-Path $Output 'Odd Uninstaller.exe')).Length | Should -BeGreaterThan 0
  }

  It 'catalogs and extracts advanced resource files through their ordinary payload records' {
    if (-not (Test-Path -LiteralPath $Script:AstrumResourceFile)) { Set-ItResult -Skipped -Because 'The controlled Astrum resource-file fixture is not cached.'; return }
    $Info = Get-AstrumInstallWizardInfo -Path $Script:AstrumResourceFile
    $Info.ResourceFiles.Path | Should -Contain '<ResourceDir>\Resource.txt'

    $Output = Join-Path $TestDrive 'resource-file'
    $Files = @(Expand-AstrumInstallWizard -Path $Script:AstrumResourceFile -DestinationPath $Output -Name '*Resource.txt' -CollisionAction Error)
    $Files.Count | Should -Be 1
    (Get-Content -LiteralPath (Join-Path $Output '_destinations\ResourceDir\Resource.txt') -Raw).TrimEnd("`r", "`n") | Should -Be 'ASTRUM RESOURCE EVIDENCE'
  }

  It 'expands a legacy 60-byte file-record layout' {
    if (-not (Test-Path -LiteralPath $Script:AstrumLegacy180)) { Set-ItResult -Skipped -Because 'The Astrum 1.x fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'legacy-expanded'
    $Files = @(Expand-AstrumInstallWizard -Path $Script:AstrumLegacy180 -DestinationPath $Output -Name '*Default.sav' -CollisionAction Error)

    $Files.Count | Should -Be 1
    $Files[0].FullName | Should -Be (Join-Path $Output 'Default.sav')
    $Files[0].Length | Should -BeGreaterThan 0
  }

  It 'honors selection, collision, entry, and byte limits' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'bounded'
    @(Expand-AstrumInstallWizard -Path $Script:AstrumProbe -DestinationPath $Output -Name '*Alpha.txt' -CollisionAction Error).Count | Should -Be 1
    @(Expand-AstrumInstallWizard -Path $Script:AstrumProbe -DestinationPath $Output -Name '*Alpha.txt' -CollisionAction Skip).Count | Should -Be 0
    { Expand-AstrumInstallWizard -Path $Script:AstrumProbe -DestinationPath (Join-Path $TestDrive 'entries') -MaximumEntries 1 -CollisionAction Error } | Should -Throw '*entry limit*'
    { Expand-AstrumInstallWizard -Path $Script:AstrumProbe -DestinationPath (Join-Path $TestDrive 'bytes') -MaximumExpandedBytes 16 -CollisionAction Error } | Should -Throw '*output limit*'
  }

  It 'streams a GZip payload across spanned companion files' {
    if (-not (Test-Path -LiteralPath $Script:AstrumSpanned) -or $Script:AstrumVolumes.Count -ne 4) { Set-ItResult -Skipped -Because 'The controlled Astrum spanned fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'spanned'
    $Files = @(Expand-AstrumInstallWizard -Path $Script:AstrumSpanned -CompanionFile $Script:AstrumVolumes -DestinationPath $Output -Name '*Large.bin' -CollisionAction Error)
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 2097152
    (Get-FileHash -LiteralPath $Files[0].FullName -Algorithm SHA256).Hash | Should -Be '6DAAD089A3B9B43079C4B59373D7B298CFB5AD463A93BB7E8C81C61328BE9E78'
  }

  It 'exports bounded raw descriptors and otherwise-unrouted pre-catalog resources' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'raw'
    $Files = @(Expand-AstrumInstallWizard -Path $Script:AstrumProbe -DestinationPath $Output -RawEntries -CollisionAction Error)

    $Files.FullName | Should -Contain (Join-Path $Output '_astrum\configuration.decoded.bin')
    @(Get-ChildItem -LiteralPath (Join-Path $Output '_astrum\records') -Filter '*.record.bin').Count | Should -Be 1
    @(Get-ChildItem -LiteralPath (Join-Path $Output '_astrum\pre-catalog') -Filter '*.bin').Count | Should -BeGreaterThan 0
  }
}

Describe 'Astrum installer analyzer and WinGet projection' {
  It 'keeps raw analysis provider-neutral and projects schema-valid WinGet evidence separately' {
    if (-not (Test-Path -LiteralPath $Script:AstrumProbe)) { Set-ItResult -Skipped -Because 'The controlled Astrum fixture is not cached.'; return }
    $Raw = Get-InstallerAnalysis -Path $Script:AstrumProbe
    $Raw.DetectedFamilies.Family | Should -Contain 'Astrum InstallWizard'
    $Raw.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'

    $WinGet = Get-WinGetInstallerAnalysis -Path $Script:AstrumProbe
    $WinGet.SuggestedManifestFields.InstallerType | Should -Be 'exe'
    $WinGet.SuggestedManifestFields.ProductCode | Should -Be 'Dumplings Astrum Probe'
    $WinGet.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/silent'
    $WinGet.SuggestedManifestFields.InstallerSuccessCodes | Should -Be @(1)
    $WinGet.SuggestedManifestFields.ElevationRequirement | Should -Be 'elevationRequired'
  }

  It 'projects the exact VM-observed BreakAlube ARP entry' {
    if (-not (Test-Path -LiteralPath $Script:BreakAlube)) { Set-ItResult -Skipped -Because 'The supplied BreakAlube installer is not cached.'; return }
    $WinGet = Get-WinGetInstallerAnalysis -Path $Script:BreakAlube

    $WinGet.SuggestedManifestFields.ProductCode | Should -Be 'PC-GINA V1.0.1.5'
    $WinGet.SuggestedManifestFields.AppsAndFeaturesEntries | Should -HaveCount 1
    $WinGet.SuggestedManifestFields.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'PC-GINA V1.0.1.5'
    $WinGet.SuggestedManifestFields.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'PC-GINA V1.0.1.5BreakAlube, PC-GINA, '
    $WinGet.SuggestedManifestFields.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '1.0.1.5'
    $WinGet.SuggestedManifestFields.AppsAndFeaturesEntries[0].Publisher | Should -Be 'Groeneveld transport efficiency b.v.'
  }

  It 'keeps silent suggestions for a compiled User Information dialog on Modern2 media' {
    $UserInformation = Join-Path $Script:AstrumVariants 'UserInfoDialog.exe'
    if (-not (Test-Path -LiteralPath $UserInformation)) { Set-ItResult -Skipped -Because 'The controlled Astrum User Information fixture is not cached.'; return }
    $WinGet = Get-WinGetInstallerAnalysis -Path $UserInformation

    $WinGet.SuggestedManifestFields.InstallModes | Should -Be @('interactive', 'silent')
    $WinGet.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/silent'
  }

  It 'projects caller elevation for as-invoker machine media' {
    $AsInvoker = Join-Path $Script:AstrumVariants 'AsInvoker.exe'
    if (-not (Test-Path -LiteralPath $AsInvoker)) { Set-ItResult -Skipped -Because 'The controlled Astrum as-invoker fixture is not cached.'; return }
    $WinGet = Get-WinGetInstallerAnalysis -Path $AsInvoker

    $WinGet.SuggestedManifestFields.Scope | Should -Be 'machine'
    $WinGet.SuggestedManifestFields.ElevationRequirement | Should -Be 'elevationRequired'
  }

  It 'projects a source-backed silent switch from a legacy runtime option table' {
    if (-not (Test-Path -LiteralPath $Script:AstrumLegacy180)) { Set-ItResult -Skipped -Because 'The Astrum 1.x fixture is not cached.'; return }
    $WinGet = Get-WinGetInstallerAnalysis -Path $Script:AstrumLegacy180

    $WinGet.SuggestedManifestFields.InstallerType | Should -Be 'exe'
    $WinGet.SuggestedManifestFields.InstallModes | Should -Be @('interactive', 'silent')
    $WinGet.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/silent'
    $WinGet.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'InstallerSuccessCodes'
  }
}
