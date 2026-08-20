. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldTestSetup.ps1')

Describe 'InstallShield cabinets and extraction' -Tag Unit {
  It 'rejects a trusted launcher whose Setup.ini has no direct external payload evidence' {
    $RuntimeFixture = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\RuntimeStubs\setup-11.exe'
    if (-not (Test-Path -LiteralPath $RuntimeFixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11 runtime fixture is unavailable.'
      return
    }
    $MediaRoot = Join-Path $TestDrive 'incomplete-external-media'
    $null = New-Item -Path (Join-Path $MediaRoot 'unrelated') -ItemType Directory -Force
    Copy-Item -LiteralPath $RuntimeFixture -Destination (Join-Path $MediaRoot 'setup.exe')
    "[Startup]`r`nEngineVersion=11.00`r`nPackageName=Missing.msi`r`n" | Set-Content -LiteralPath (Join-Path $MediaRoot 'Setup.ini') -NoNewline
    [IO.File]::WriteAllText((Join-Path $MediaRoot 'unrelated\setup.inx'), 'not direct media')

    $ExternalMedia = InModuleScope InstallShield -Parameters @{ InstallerPath = Join-Path $MediaRoot 'setup.exe' } {
      param($InstallerPath)
      Get-InstallShieldExternalMediaInfo -Path $InstallerPath
    }

    $ExternalMedia | Should -BeNullOrEmpty
  }

  It 'routes official 11.5 external InstallScript media without scanning the sibling directory' {
    $FixtureRoot = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\DialogSamplerDefault'
    $Fixture = Join-Path $FixtureRoot 'setup.exe'
    $Header = Join-Path $FixtureRoot 'data1.hdr'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf) -or -not (Test-Path -LiteralPath $Header -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11.5 Dialog Sampler media fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be '9F592BA27A79B32D11FAFA59FACBBEBDC9902410E37E2EAFA22E677FC33F47E6'
    Get-DumplingsTestFixtureHash -Path $Header | Should -Be 'EB1D501D8D01B9EEFFE7C2A3A5C1B345C20016894E0F5DD54A7272CEB59A3C7E'

    $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath (Join-Path $TestDrive 'dialog-sampler')

    $Info.ContainerFormat | Should -Be 'InstallShield External Media'
    $Info.Variant | Should -Be 'InstallScript'
    $Info.InstallShieldProjectType | Should -Be 'InstallScript'
    $Info.ProductCode | Should -Be '{40F1A2C0-2DB0-11D3-803F-00104B1F989C}'
    $Info.DisplayName | Should -Be 'InstallShield Dialog Sampler'
    $Info.Publisher | Should -Be 'Macrovision'
    $Info.ExternalMediaInfo.EngineVersion | Should -Be '11.50.0.42618'
    $Info.ExternalMediaInfo.MediaRoot | Should -Be $FixtureRoot
    $Info.InxFiles | Should -HaveCount 1
    $Info.InxFiles[0] | Should -Be (Join-Path $FixtureRoot 'setup.inx')
    $Info.InstallShieldCabinetSupport.CatalogEntryCount | Should -Be 57
    $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 11.5'
    $Info.InstallShieldRelease.Build | Should -Be '42618'
    $Info.InstallShieldRelease.Confidence | Should -Be 'StructuredEngineVersion'
    $Info.InstallShieldRelease.Diagnostics | Should -BeNullOrEmpty
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Be @('Media/External', 'Cabinet6/AnsiCatalog', 'Script/aLuZ')
  }

  It 'routes archived 6.10 uppercase external media through the ANSI catalog and aLuZ script' {
    $FixtureRoot = Join-Path $Script:InstallShieldBuilderRoot '6.10\ArchivedMedia\Media'
    $Fixture = Join-Path $FixtureRoot 'SETUP.EXE'
    $Header = Join-Path $FixtureRoot 'DATA1.HDR'
    $SecondVolume = Join-Path $FixtureRoot 'DATA2.CAB'
    $Inx = Join-Path $FixtureRoot 'SETUP.INX'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf) -or -not (Test-Path -LiteralPath $Header -PathType Leaf) -or -not (Test-Path -LiteralPath $SecondVolume -PathType Leaf) -or -not (Test-Path -LiteralPath $Inx -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The archived InstallShield Professional 6.10 media fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be '20B0C376813A4DAC5387E48D504AED1DD5380AE11EA0E4EAB05DF81CD0BF0D53'
    Get-DumplingsTestFixtureHash -Path $Header | Should -Be 'B32620024598F5D492B44950CADBF791800553BAE51860811B0852F74C4ED334'
    Get-DumplingsTestFixtureHash -Path $SecondVolume | Should -Be '1207D1865DC7E397B2C79EE873649224E9DE389A492F737AC2E04564CC6AF08C'
    Get-DumplingsTestFixtureHash -Path $Inx | Should -Be 'EB4096111984AD9C989C9F9421CCB97FBF210B1A63ED744C4CADE7A2D0787EE6'

    $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath (Join-Path $TestDrive 'installshield-610')

    $Info.ContainerFormat | Should -Be 'InstallShield External Media'
    $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield Professional 6'
    $Info.InstallShieldRelease.Build | Should -Be '100.1249'
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Be @('Media/External', 'Cabinet6/AnsiCatalog', 'Script/aLuZ')
    $Info.InstallShieldCabinetSupport.CatalogEntryCount | Should -Be 2014
    $Info.InstallShieldCabinetSupport.MediaVersions.RawVersion | Should -Be ([uint32]0x0100600C)
    $Info.InstallShieldCabinetSupport.MediaVersions.StructuralProfile | Should -Be 'AnsiCatalog'
    $Info.InstallShieldCabinetSupport.MediaVersions.Limitations | Should -Match 'generation-specific optional registry and shell pointer layouts'
    $Info.InstallShieldCabinetSupport.Diagnostics | Should -BeNullOrEmpty
    $Info.InstallScriptInfo.ParserVersionInfo.HeaderKind | Should -Be 'aLuZ'
    $Info.InstallScriptInfo.ParserVersionInfo.InstructionCount | Should -BeGreaterThan 10000
    $Info.UnsupportedOpcodes | Should -BeNullOrEmpty

    $SelectedDestination = Join-Path $TestDrive 'installshield-610-selected'
    $null = Expand-InstallShieldCabinet -Path $Header -DestinationPath $SelectedDestination -Name '_disk1.cdf' -CollisionAction Error
    Get-DumplingsTestFixtureHash -Path (Join-Path $SelectedDestination '_disk1.cdf') | Should -Be 'D461C503977AD961D41F8ECDBF2AFAECA75DD5AB5BF1A6837CEF741D7B67EE2E'
  }

  It 'classifies the official InstallShield 3 engine without treating it as package media' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '3\ClassicMedia\setup32.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 3 engine fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be '3AAA614FDF6986017CBE6ADE045D404F08872E6A90D6A0D54C30E438A2BDEE65'
    $Destination = Join-Path $TestDrive 'classic-engine'

    $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $Destination

    $Info.ContainerFormat | Should -Be 'InstallShield 3 Engine'
    $Info.Variant | Should -Be 'InstallShield 3 engine without package media'
    $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 3'
    $Info.InstallShieldRelease.Build | Should -Be '117'
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Be 'Classic3/Engine'
    $Info.InstallShieldStructuralRoutes.SupportStatus | Should -Be 'Partial'
    $Info.ExtractedFiles | Should -BeNullOrEmpty
    $Info.Diagnostics.Message | Should -Match 'without a validated embedded Setup30 package'
  }

  It 'extracts InstallShield 3 Setup30 footer members through bounded TTCOMP decoding' {
    $Archive = Join-Path $TestDrive 'data.z'
    $Destination = Join-Path $TestDrive 'classic-expanded'
    New-TestInstallShieldClassicArchive -Path $Archive

    $Info = Get-InstallShieldClassicArchiveInfo -Path $Archive
    $Files = @(Expand-InstallShieldClassicArchive -Path $Archive -DestinationPath $Destination -CollisionAction Error)

    $Info.Profile | Should -Be 'Setup30FooterTtComp'
    $Info.Entries.Name | Should -Be 'A.TXT'
    [IO.File]::ReadAllText($Files[0]) | Should -Be 'AIAIAIAIAIAIA'
  }

  It 'rejects a truncated InstallShield 3 footer without scanning beyond the bounded tail' {
    $Archive = Join-Path $TestDrive 'truncated-data.z'
    [IO.File]::WriteAllBytes($Archive, [byte[]](0x00, 0x04, 0x82, 0x24, 0x25, 0x8F))

    { Get-InstallShieldClassicArchiveInfo -Path $Archive } | Should -Throw '*no validated Setup30 footer entries*'
  }

  It 'extracts InstallShield 5 descriptors and raw-Deflate volume records' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $Expected = New-TestInstallShield5Cabinet -Path $HeaderPath
    $Destination = Join-Path $TestDrive 'legacy-five-expanded'

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($HeaderPath)
    $null = Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath $Destination -CollisionAction Error

    $Inspection.MediaMetadata.RawVersion | Should -Be ([uint32]0x01005000)
    $Inspection.MediaMetadata.MajorVersion | Should -Be 5
    $Inspection.MediaMetadata.StructuralProfile | Should -Be 'LegacyDescriptor'
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\legacy.bin')) | Should -Be $Expected
  }

  It 'catalogs and extracts an archived pre-digest InstallShield 5 cabinet' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '5\ArchivedMedia\IS5pro_u\data1.cab'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The extracted InstallShield 5 Professional cabinet fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be 'A6DEC4E8A2D7BC4810711DD5F4F10F71F7A8E52A6B9B834AE306CA5076A66B0E'
    $Destination = Join-Path $TestDrive 'legacy-zero-expanded'

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Fixture)
    $null = Expand-InstallShieldCabinet -Path $Fixture -DestinationPath $Destination -Name 'Version.txt' -CollisionAction Error

    $Inspection.Entries.Count | Should -Be 451
    @($Inspection.Entries | Where-Object IsValid).Count | Should -Be 351
    $Inspection.MediaMetadata.RawVersion | Should -Be ([uint32]0x01000004)
    $Inspection.MediaMetadata.MajorVersion | Should -Be 0
    $Inspection.MediaMetadata.StructuralProfile | Should -Be 'LegacyDescriptorWithoutDigest'
    [IO.File]::ReadAllText((Join-Path $Destination 'Version.txt')) | Should -Be "[Version]`r`nBuild=200"
  }

  It 'rejects an InstallShield 5 descriptor whose expanded-data MD5 is incorrect' {
    $HeaderPath = Join-Path $TestDrive 'bad-md5\data1.hdr'
    $null = New-Item -Path (Split-Path -Path $HeaderPath -Parent) -ItemType Directory -Force
    $null = New-TestInstallShield5Cabinet -Path $HeaderPath
    $Header = [IO.File]::ReadAllBytes($HeaderPath)
    # Descriptor starts at 0xA0 in the generated fixture; MD5 is +0x2A.
    $Header[0xCA] = $Header[0xCA] -bxor 0xFF
    [IO.File]::WriteAllBytes($HeaderPath, $Header)

    { Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath (Join-Path $TestDrive 'bad-md5-expanded') -CollisionAction Error } |
      Should -Throw '*MD5*'
  }

  It 'streams compressed split entries across volumes and resolves linked aliases' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $Fixture = New-TestInstallShieldSpannedCabinet -Path $HeaderPath
    $Destination = Join-Path $TestDrive 'spanned-expanded'

    $Result = Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath $Destination -CollisionAction Error

    $Result | Should -Be (Get-Item -LiteralPath $Destination).FullName
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\split.bin')) | Should -Be $Fixture.Payload
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\alias.bin')) | Should -Be $Fixture.Payload
  }

  It 'rejects cyclic InstallShield cabinet link chains before opening payload volumes' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $null = New-TestInstallShieldSpannedCabinet -Path $HeaderPath
    $Header = [IO.File]::ReadAllBytes($HeaderPath)
    $FirstDescriptor = 0x20 + 0x100 + 0x100
    [BitConverter]::GetBytes([uint32]1).CopyTo($Header, $FirstDescriptor + 76)
    $Header[$FirstDescriptor + 84] = 1
    [IO.File]::WriteAllBytes($HeaderPath, $Header)

    { Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath (Join-Path $TestDrive 'cycle') -Name 'split.bin' -CollisionAction Error } |
      Should -Throw '*link chain contains a cycle*'
  }

  It 'builds one analysis context with one extraction, tree walk, and nested MSI parse' {
    $Fixture = Join-Path $TestDrive 'context-setup.exe'
    $Destination = Join-Path $TestDrive 'context-expanded'
    $MsiPath = Join-Path $Destination 'selected.msi'
    [IO.File]::WriteAllBytes($Fixture, [byte[]](0x4D, 0x5A, 0, 0))
    $null = New-Item -Path $Destination -ItemType Directory -Force
    [IO.File]::WriteAllBytes($MsiPath, [byte[]](0))

    InModuleScope InstallShield -Parameters @{ Fixture = $Fixture; Destination = $Destination; MsiPath = $MsiPath } {
      param($Fixture, $Destination, $MsiPath)
      Mock Get-PEOverlayOffset { 0 }
      Mock Invoke-InstallShieldExtractionWithClassicFallback { [pscustomobject]@{ Result = $Destination; Files = @() } }
      Mock Expand-InstallShieldCabinetSupport { [pscustomobject]@{ ExtractedFiles = @(); Diagnostics = @() } }
      Mock Get-ChildItem { @(Get-Item -LiteralPath $MsiPath) }
      Mock Get-InstallShieldMsiPayloadSelection {
        [pscustomobject]@{ Configuration = $null; SelectedMsiPath = $MsiPath; SelectionSource = 'Test'; Diagnostics = @() }
      }
      Mock Resolve-InstallShieldMsiFile { Get-Item -LiteralPath $MsiPath }
      Mock Get-MsiInstallerInfo { [pscustomobject]@{ InstallShieldProjectType = 'Basic MSI' } }

      $Context = New-InstallShieldAnalysisContext -Path $Fixture -DestinationPath $Destination

      $Context.Variant | Should -Be 'Basic MSI'
      Should -Invoke Invoke-InstallShieldExtractionWithClassicFallback -Exactly 1
      Should -Invoke Expand-InstallShieldCabinetSupport -Exactly 1
      Should -Invoke Get-ChildItem -Exactly 1
      Should -Invoke Get-InstallShieldMsiPayloadSelection -Exactly 1
      Should -Invoke Get-MsiInstallerInfo -Exactly 1
    }
  }

  It 'parses NB10-prefixed CastleDriver launchers from both architecture payloads' {
    foreach ($Fixture in @(Get-CastleDriverInstallerFixture)) {
      $ExpandedPath = Join-Path $TestDrive "castle-driver-$($Fixture.Architecture)"
      $Info = Get-InstallShieldInfo -Path $Fixture.Path -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.ContainerFormat | Should -Be 'InstallShield Overlay'
      $Info.SelectedMsiPath | Should -Be 'CAS CDC Driver.msi'
      $Info.Diagnostics | Should -BeNullOrEmpty
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2010'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Overlay/InstallShield'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'MSI/Basic'
      $MsiInfo.DisplayName | Should -Be 'CAS CDC Driver'
      $MsiInfo.DisplayVersion | Should -Be $Fixture.DisplayVersion
      $MsiInfo.ProductCode | Should -Be $Fixture.ProductCode
      $MsiInfo.UpgradeCode | Should -Be $Fixture.UpgradeCode
      $MsiInfo.Scope | Should -Be 'machine'
      $MsiInfo.InstallLocationSwitch | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
    }
  }

  It 'Should retain the legacy extraction command without depending on ISx.exe' {
    Get-ChildItem (Join-Path $Script:DumplingsModuleRoot 'Assets') -Filter 'ISx.exe' -File -Recurse |
      Should -BeNullOrEmpty

    InModuleScope InstallShield {
      Mock Expand-InstallShieldInstaller { 'C:\Extracted\Setup_u' }

      Expand-InstallShield -Path 'C:\Fixtures\Setup.exe' -CollisionAction Rename | Should -Be 'C:\Extracted\Setup_u'
      Should -Invoke Expand-InstallShieldInstaller -Exactly 1 -ParameterFilter {
        $Path -eq 'C:\Fixtures\Setup.exe' -and [string]::IsNullOrEmpty($DestinationPath) -and
        $MaximumExpandedBytes -eq 8GB
      }
    }
  }

  It 'Should distinguish type 3 ISSetupStream attributes with and without timestamps' {
    InModuleScope InstallShield {
      $NameBytes = [Text.Encoding]::Unicode.GetBytes("Setup.inx$([char]0)")
      $Payload = [byte[]](1, 2, 3, 4)
      $Record = [byte[]]::new(24 + 24 + $NameBytes.Length + $Payload.Length)
      [BitConverter]::GetBytes([uint32]$NameBytes.Length).CopyTo($Record, 0)
      [BitConverter]::GetBytes([uint32]6).CopyTo($Record, 4)
      [BitConverter]::GetBytes([uint32]$Payload.Length).CopyTo($Record, 10)
      [BitConverter]::GetBytes([uint16]1).CopyTo($Record, 22)
      for ($Index = 0; $Index -lt 3; $Index++) {
        [BitConverter]::GetBytes(([datetime]'2026-01-02T03:04:05Z').ToFileTimeUtc()).CopyTo($Record, 24 + $Index * 8)
      }
      $NameBytes.CopyTo($Record, 48)
      $Payload.CopyTo($Record, 48 + $NameBytes.Length)

      $Stream = [IO.MemoryStream]::new($Record)
      try {
        $Attribute = Get-InstallShieldStreamAttribute -Stream $Stream -Offset 0 -Type 3

        $Attribute.FileName | Should -Be 'Setup.inx'
        $Attribute.FileLength | Should -Be $Payload.Length
        $Attribute.DataOffset | Should -Be (48 + $NameBytes.Length)
      } finally {
        $Stream.Dispose()
      }

      $RecordWithoutTimestamps = [byte[]]::new(24 + $NameBytes.Length + $Payload.Length)
      [BitConverter]::GetBytes([uint32]$NameBytes.Length).CopyTo($RecordWithoutTimestamps, 0)
      [BitConverter]::GetBytes([uint32]6).CopyTo($RecordWithoutTimestamps, 4)
      [BitConverter]::GetBytes([uint32]$Payload.Length).CopyTo($RecordWithoutTimestamps, 10)
      [BitConverter]::GetBytes([uint16]1).CopyTo($RecordWithoutTimestamps, 22)
      $NameBytes.CopyTo($RecordWithoutTimestamps, 24)
      $Payload.CopyTo($RecordWithoutTimestamps, 24 + $NameBytes.Length)
      $Stream = [IO.MemoryStream]::new($RecordWithoutTimestamps)
      try {
        $Attribute = Get-InstallShieldStreamAttribute -Stream $Stream -Offset 0 -Type 3
        $Attribute.FileName | Should -Be 'Setup.inx'
        $Attribute.DataOffset | Should -Be (24 + $NameBytes.Length)
      } finally {
        $Stream.Dispose()
      }
    }
  }
}
