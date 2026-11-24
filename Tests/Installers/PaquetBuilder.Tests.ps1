. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive
  $Script:PaquetFixtureRoot = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\PaquetBuilder\GDGSoftware.PaquetBuilder'
}

Describe 'Paquet Builder static parser' {
  It 'Should populate both WinGet unattended switch slots for current silent-capable media' {
    $Path = Join-Path $Script:PaquetFixtureRoot 'current\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent current Paquet Builder fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.InstallerSwitches.Silent | Should -Be '/s'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/s'
  }

  It 'Should classify independent payload and runtime archives without assuming physical order' {
    $PayloadBytes = [Convert]::FromBase64String('N3q8ryccAAQ9qmANEQAAAAAAAABaAAAAAAAAAMFZj+oBAAzvu79NWiBwYXlsb2FkAAEEBgABCREABwsBAAEhIQEADA0ACAoBlIuc5QAABQEZDAAAAAAAAAAAAAAAABERAGEAcABwAC4AZQB4AGUAAAAZAgAAFAoBAB62AVRLEN0BFQYBACAAAAAAAA==')
    $RuntimeBytes = [Convert]::FromBase64String('N3q8ryccAARvFqxziQAAAAAAAAAhAAAAAAAAAIeEEHoBABHvu79NWiBjb3Jl77u/cHJvcHMAAACBMweuD89dLwwHyEN/QbH6/eXHfeltPRF+KAQ4jdN8i3B2bHASkmtshsURP/CTxIVxKBlS3RJpSTQfS1uagxDwitrxEOECC63BwAFZFPCO/UlgqXK0gK4zcbXJH8lrfwIF5lsbjlRuLVrCC1IqcmXAABcGFgEJcwAHCwEAASMDAQEFXQAQAAAMgIYKASqU5xkAAA==')
    $FixturePath = Join-Path $Script:FixtureDirectory 'paquet-archives.exe'
    Copy-Item -LiteralPath (Get-Process -Id $PID).Path -Destination $FixturePath
    $Output = [IO.File]::Open($FixturePath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $Output.Write($PayloadBytes)
      $Output.Write([byte[]]::new(73))
      $Output.Write($RuntimeBytes)
    } finally {
      $Output.Dispose()
    }

    InModuleScope PaquetBuilder -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      $ArchiveData = Get-PaquetBuilderArchiveData -Path $FixturePath
      $ArchiveData.Profile.Id | Should -Be 'SplitArchiveRuntime'
      $ArchiveData.Payload.Entries.FullName | Should -Be @('app.exe')
      $ArchiveData.Runtime.Entries.FullName | Should -Contain 'pbfprop.dat'
      $ArchiveData.Runtime.Entries.FullName | Should -Contain 'PBCore64.dll'
      $ArchiveData.Payload.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
      $ArchiveData.Runtime.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
    }
  }

  It 'Should materialize a zero-length archive entry without asking SharpCompress for a stream' {
    $NativeEntry = [pscustomobject]@{}
    $NativeEntry | Add-Member -MemberType ScriptMethod -Name OpenEntryStream -Value { throw 'The native zero-length stream must not be opened.' }
    $Entry = [pscustomobject]@{ FullName = 'empty.dat'; Length = 0L; NativeEntry = $NativeEntry }

    $Stream = Open-InstallerArchiveEntry -Entry $Entry
    try { $Stream.Length | Should -Be 0 } finally { $Stream.Dispose() }
  }

  It 'Should classify the classic resource-package generation' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20000914091301\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent Paquet Builder 2.6 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'ClassicResourcePackage'
    $Info.FormatGeneration | Should -Be 'Classic2'
    $Info.DisplayVersion | Should -Be '2.6.0'
    $Info.ClassicEnvelope.ExpectedCrc32 | Should -Be 0x7050666F
    $Info.ClassicEnvelope.ArchiveOffset | Should -Be 76376
    $Info.Diagnostics.Id | Should -Contain 'PaquetBuilder.Extraction.ClassicArchiveIncomplete'
  }

  It 'Should validate and expand a complete Classic GPacker and ZIP package' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20010415133655\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent complete Paquet Builder 2.6 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path
    $Destination = Join-Path $Script:FixtureDirectory 'classic-package'
    $Files = @(Expand-PaquetBuilderInstaller -Path $Path -DestinationPath $Destination -Name 'PBuilder.exe' -CollisionAction Error)

    $Info.ClassicEnvelope.ExpectedCrc32 | Should -Be 0x7050666F
    $Info.ClassicCatalog.ControllerEntry | Should -Be 'SETUP.EXE'
    $Info.ClassicCatalog.GafEntry | Should -Be 'SETUP1.GAF'
    $Info.ClassicCatalog.Metadata.Counts.File | Should -Be 28
    $Info.ClassicCatalog.Metadata.Counts.Shortcut | Should -Be 6
    $Info.ClassicCatalog.Metadata.Counts.Registry | Should -Be 20
    $Info.PayloadFiles | Should -Contain '{app}\PBuilder.exe'
    $Info.PayloadFiles | Should -Contain '{win}\GUNINST.EXE'
    $Info.RegistryWrites.Count | Should -Be 20
    $Info.FileExtensions | Should -Be @('pbp', 'pbr')
    $Info.Scope | Should -Be 'machine'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Not -Contain 'PaquetBuilder.Extraction.ClassicInstalledPathsUnresolved'
    $Files.Name | Should -Be 'PBuilder.exe'
    $Files[0].Length | Should -Be 555008
    (Get-FileHash -LiteralPath $Files[0].FullName -Algorithm SHA256).Hash | Should -Be 'DBB2FA1F2B4245E7151E1EEC1A1D9DCF6B94426A495875EE78007116F147A2B3'
  }

  It 'Should reject a Classic package whose GPacker control stream no longer matches its CRC' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20010415133655\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent complete Paquet Builder 2.6 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path
    $CorruptPath = Join-Path $Script:FixtureDirectory 'paquet-classic-corrupt.exe'
    Copy-Item -LiteralPath $Path -Destination $CorruptPath
    $Stream = [IO.File]::Open($CorruptPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
      $Stream.Position = $Info.ClassicEnvelope.CompressedOffset + 32
      $Value = $Stream.ReadByte()
      $Stream.Position = $Stream.Position - 1
      $Stream.WriteByte([byte]($Value -bxor 1))
    } finally {
      $Stream.Dispose()
    }

    { Get-PaquetBuilderInfo -Path $CorruptPath } | Should -Throw
  }

  It 'Should classify the ISFX cabinet-package generation from exact descriptor offsets' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20021007004621\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent Paquet Builder 2.7 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'CabinetPackageRuntime'
    $Info.FormatGeneration | Should -Be 'Cabinet2'
    $Info.IsfxDescriptor.PackageOffset | Should -Be 76288
    $Info.IsfxDescriptor.PayloadOffset | Should -Be 88458
    $Info.PayloadFiles | Should -Be @('PBSetup.msi', 'PBSetup1.cab')
    $Info.ProductCode | Should -Be '{92624FCF-ECCC-4275-9838-2CF09C9785D9}'
    $Info.UpgradeCode | Should -Be '{DE35F0CD-1ADA-41FC-A62A-66B8060D24AB}'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.PackageConfiguration.Format | Should -Be 'GDG-LZHUF'
    $Info.PackageConfiguration.Resources.Count | Should -Be 13
    $Info.PackageConfiguration.UncompressedSize | Should -Be 49515
    $Info.PackageConfiguration.ActualCrc32 | Should -Be ([uint32]2728951343)
    $Info.PackageConfiguration.DecoderPaddingBytes | Should -Be 1
    $Info.PackageScript.Text | Should -Match 'Generated Script for Paquet Builder 2\.7\.1\.1'
    $Info.PackageScript.ExecutedPayloads.Path | Should -Be '%SYS%\MSIExec.exe'
    $Info.PackageScript.ExecutedPayloads.Arguments | Should -Be '/i %DESTPATH%\PBSetup.msi'
    $Info.Diagnostics.Id | Should -Not -Contain 'PaquetBuilder.Metadata.CabinetConfigurationOpaque'

    $Destination = Join-Path $Script:FixtureDirectory 'cabinet-package'
    $Files = @(Expand-PaquetBuilderInstaller -Path $Path -DestinationPath $Destination -Name 'PBSetup.msi' -CollisionAction Error)
    $Files.Name | Should -Be 'PBSetup.msi'
    (Get-MsiInstallerInfo -Path $Files[0].FullName).ProductCode | Should -Be $Info.ProductCode
  }

  It 'Should keep a non-MSI Cabinet2 payload as package evidence without inventing ARP identity' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20020614181040\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent non-MSI Paquet Builder 2.7 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'CabinetPackageRuntime'
    $Info.PayloadFiles | Should -Be @('setup-1.bin', 'setup.0', 'setup.exe', 'setup.msg')
    $Info.NestedMsiPath | Should -BeNullOrEmpty
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.PackageConfiguration.Format | Should -Be 'GDG-LZHUF'
    $Info.PackageConfiguration.Resources.Count | Should -Be 10
    $Info.PackageConfiguration.UncompressedSize | Should -Be 69861
    $Info.PackageConfiguration.ActualCrc32 | Should -Be 0x73916043
    $Info.PackageScript.ExecutedPayloads.Path | Should -Be '%DESTPATH%\setup.exe'

    $Destination = Join-Path $Script:FixtureDirectory 'cabinet-package-non-msi'
    $Files = @(Expand-PaquetBuilderInstaller -Path $Path -DestinationPath $Destination -Name 'setup.msg' -CollisionAction Error)
    $Files.Name | Should -Be 'setup.msg'
  }

  It 'Should recover the nested MSI identity from the 2.8 wrapper generation' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20031208150923\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent Paquet Builder 2.8 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'LegacyEmbeddedPeRuntime'
    $Info.NestedMsiPath | Should -Be 'PBSetup.msi'
    $Info.ProductCode | Should -Be '{1B272475-6F41-4FAA-8DB0-57E4E7DC259D}'
    $Info.UpgradeCode | Should -Be '{F0867104-9AF6-4CF4-8B71-D591E2230CFE}'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.PackageConfiguration.Format | Should -Be 'AP32'
    $Info.PackageConfiguration.ExpectedCompressedCrc32 | Should -Be 0x55E01836
    $Info.PackageConfiguration.UncompressedSize | Should -Be 78198
    $Info.PackageConfiguration.ActualCrc32 | Should -Be 0x487977EF
    $Info.PackageConfiguration.Resources.Count | Should -BeGreaterThan 0
    $Info.PackageScript.Text | Should -Match 'Generated Script for Paquet Builder 2\.8'
    $Info.Diagnostics.Id | Should -Not -Contain 'PaquetBuilder.Metadata.PackageConfigurationCompressionUnsupported'
  }

  It 'Should reject AP32 configuration data that fails its compressed CRC' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20031208150923\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent Paquet Builder 2.8 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path
    $CorruptPath = Join-Path $Script:FixtureDirectory 'paquet-ap32-corrupt.exe'
    Copy-Item -LiteralPath $Path -Destination $CorruptPath
    $Stream = [IO.File]::Open($CorruptPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
      $Stream.Position = $Info.IsfxDescriptor.PackageOffset + 24 + 32
      $Value = $Stream.ReadByte()
      $Stream.Position--
      $Stream.WriteByte([byte]($Value -bxor 1))
    } finally {
      $Stream.Dispose()
    }

    $CorruptInfo = Get-PaquetBuilderInfo -Path $CorruptPath
    $CorruptInfo.PackageConfiguration | Should -BeNullOrEmpty
    $CorruptInfo.Diagnostics.Id | Should -Contain 'PaquetBuilder.Metadata.PackageConfigurationInvalid'
    ($CorruptInfo.Diagnostics | Where-Object Id -EQ 'PaquetBuilder.Metadata.PackageConfigurationInvalid').Message | Should -Match 'compressed configuration fails its CRC32 check'
  }

  It 'Should decode and expand the GP-framed 2.9 runtime' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20051018202420\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent Paquet Builder 2.9 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'CompressedResourceRuntime'
    $Info.PayloadFiles.Count | Should -BeGreaterThan 1
    $Info.ProductCode | Should -Be '{6BC83C7A-96A4-4B9E-8FFE-1DAB39ECF466}'
    $Info.UpgradeCode | Should -Be '{F0867104-9AF6-4CF4-8B71-D591E2230CFE}'
    $Info.NestedMsiPath | Should -Be 'Setup1.msi'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.RuntimeResourceInfo.UncompressedSize | Should -Be 252928
    $Info.RuntimeFiles | Should -Be @('ENG.exe', 'ENG.tail.bin')
    $Info.PackageConfiguration.Format | Should -Be 'GP-LZMA'
    $Info.PackageConfiguration.Resources.Count | Should -Be 29
    $Info.PackageConfiguration.UncompressedSize | Should -Be 211648
    $Info.PackageConfiguration.ActualCrc32 | Should -Be ([Convert]::ToUInt32('D37750B5', 16))
    $Info.PackageConfiguration.DecoderTrailingBytes | Should -Be 4
    $Info.PackageScript.Text | Should -Match 'Generated Script for Paquet Builder 2\.9'
    $Info.Diagnostics.Id | Should -Not -Contain 'PaquetBuilder.Runtime.GpTransformUnsupported'
    $Info.Diagnostics.Id | Should -Not -Contain 'PaquetBuilder.Runtime.GpTrailingDataOpaque'

    $Destination = Join-Path $Script:FixtureDirectory 'gp-runtime'
    $Runtime = @(Expand-PaquetBuilderInstaller -Path $Path -DestinationPath $Destination -ArchiveKind Runtime -CollisionAction Error)
    $Runtime.Name | Should -Be @('ENG.exe', 'ENG.tail.bin')
    (Get-PELayout -Path (Join-Path $Destination 'ENG.exe')).Machine | Should -Be 0x014C
  }

  It 'Should decode the same GP package framing across later 2.9 releases' -ForEach @(
    @{ Capture = '20070813134915'; Version = '2.9.5.0'; Size = 252171; Crc32 = [Convert]::ToUInt32('4175A390', 16) }
    @{ Capture = '20110528081157'; Version = '2.9.6.0'; Size = 256646; Crc32 = [Convert]::ToUInt32('EA56C32B', 16) }
  ) {
    $Path = Join-Path $Script:PaquetFixtureRoot "$Capture\pbinst.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "The persistent Paquet Builder $Version fixture is unavailable."; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'CompressedResourceRuntime'
    $Info.DisplayVersion | Should -Be $Version
    $Info.PackageConfiguration.Format | Should -Be 'GP-LZMA'
    $Info.PackageConfiguration.Resources.Count | Should -Be 29
    $Info.PackageConfiguration.UncompressedSize | Should -Be $Size
    $Info.PackageConfiguration.ActualCrc32 | Should -Be $Crc32
    $Info.PackageConfiguration.DecoderTrailingBytes | Should -Be 4
    $Info.ProductCode | Should -Be 'PaquetBuilderSetup89'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Paquet Builder'
    $Info.DisplayIcon | Should -Be '%ProgramFiles%\Paquet Builder\PBuilder.exe'
    $Info.UninstallString | Should -Be '%ProgramFiles%\Paquet Builder\Uninst.exe'
    $Info.FileExtensions | Should -Be @('pbd', 'pbp', 'pbr')
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UnresolvedFields | Should -BeNullOrEmpty
    $Info.RegistryWrites.Count | Should -Be 48
    $Info.Shortcuts.Count | Should -Be 6
    $Info.FileOperations.Count | Should -Be 6
    $Info.UninstallOperations.Count | Should -Be 8
    $Info.PackageScript.UnsupportedCommands | Should -Be @('AUTOSC')
    $Info.Diagnostics.Id | Should -Contain 'PaquetBuilder.Script.CommandsUnsupported'
  }

  It 'Should recover literal ARP identity from a modern split-archive package' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20210212001753\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent Paquet Builder 20.1 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'SplitArchiveRuntime'
    $Info.ProductCode | Should -Be 'GDGSoftPB2019'
    $Info.RuntimeCatalog.HasUninstallerTemplate | Should -BeTrue
    $Info.RuntimeCatalog.PropertyRecords.Count | Should -BeGreaterThan 0
  }

  It 'Should reconstruct integrity-checked UPX launchers before scanning native metadata' -ForEach @(
    @{ Capture = '20131212015927'; Version = '3.0.4.0'; AssignmentCount = 47 }
    @{ Capture = '20181105184446'; Version = '3.2.0.0'; AssignmentCount = 52 }
  ) {
    $Path = Join-Path $Script:PaquetFixtureRoot "$Capture\pbinst.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "The persistent Paquet Builder $Version fixture is unavailable."; return }

    $Info = Get-PaquetBuilderInfo -Path $Path

    $Info.StructuralRoute | Should -Be 'SplitArchiveRuntime'
    $Info.DisplayVersion | Should -Be $Version
    $Info.PackedPeInfo.Format | Should -Be 'UPX-LZMA'
    $Info.PackedPeInfo.HeaderVersion | Should -Be 13
    $Info.CompiledVariableAssignments.Count | Should -Be $AssignmentCount
    @($Info.CompiledVariableAssignments | Where-Object { $_.Name -ceq 'UNINSTKEY' -and $_.Value -ceq 'GDGSoftPB300' }).Count | Should -Be 1
    $Info.ProductCode | Should -Be 'GDGSoftPB300'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Paquet Builder 3'
    $Info.SupportsSilentInstallation | Should -BeFalse
    $Info.Diagnostics.Id | Should -Contain 'PaquetBuilder.Script.PackedPeRecovered'
    $Info.UnresolvedFields | Should -BeNullOrEmpty
  }

  It 'Should preserve container evidence but reject corrupted UPX script metadata' {
    $Path = Join-Path $Script:PaquetFixtureRoot '20131212015927\pbinst.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The persistent Paquet Builder 3.0 fixture is unavailable.'; return }

    $Info = Get-PaquetBuilderInfo -Path $Path
    $CorruptPath = Join-Path $Script:FixtureDirectory 'paquet-upx-corrupt.exe'
    Copy-Item -LiteralPath $Path -Destination $CorruptPath
    $Stream = [IO.File]::Open($CorruptPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
      $Stream.Position = $Info.PackedPeInfo.CompressedOffset + 32
      $Value = $Stream.ReadByte()
      $Stream.Position--
      $Stream.WriteByte([byte]($Value -bxor 1))
    } finally {
      $Stream.Dispose()
    }

    $CorruptInfo = Get-PaquetBuilderInfo -Path $CorruptPath
    $CorruptInfo.StructuralRoute | Should -Be 'SplitArchiveRuntime'
    $CorruptInfo.ProductCode | Should -BeNullOrEmpty
    $CorruptInfo.Diagnostics.Id | Should -Contain 'PaquetBuilder.Script.ScanIncomplete'
    ($CorruptInfo.Diagnostics | Where-Object Id -EQ 'PaquetBuilder.Script.ScanIncomplete').Message | Should -Match 'compressed image fails its Adler-32 check'
    $CorruptInfo.UnresolvedFields | Should -Contain 'ProductCode'
  }
}
