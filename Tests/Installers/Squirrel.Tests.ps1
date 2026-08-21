. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerDiagnostics.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PEDependency.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'Squirrel.psm1') -Force

  $Script:FixtureDirectory = $TestDrive

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url
  }

  function New-SquirrelLibraryBundleFixture {
    $Path = Join-Path $TestDrive 'SquirrelLibraryBundle.exe'
    $Bytes = [byte[]]::new(4096)
    $HeaderOffset = 512
    $MarkerOffset = 128
    [BitConverter]::GetBytes([int64]$HeaderOffset).CopyTo($Bytes, $MarkerOffset)
    $BundleSignature = [byte[]](0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32, 0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae)
    $BundleSignature.CopyTo($Bytes, $MarkerOffset + 8)
    [BitConverter]::GetBytes([uint32]6).CopyTo($Bytes, $HeaderOffset)
    [BitConverter]::GetBytes([uint32]0).CopyTo($Bytes, $HeaderOffset + 4)
    [BitConverter]::GetBytes([int32]2).CopyTo($Bytes, $HeaderOffset + 8)
    $BundleId = [Text.Encoding]::UTF8.GetBytes('FakeBundleID')
    $Bytes[$HeaderOffset + 12] = [byte]$BundleId.Length
    $BundleId.CopyTo($Bytes, $HeaderOffset + 13)
    $EntryOffset = $HeaderOffset + 13 + $BundleId.Length + 40
    foreach ($Name in @('NuGet.Squirrel.dll', 'Squirrel.dll')) {
      [BitConverter]::GetBytes([int64]0).CopyTo($Bytes, $EntryOffset)
      [BitConverter]::GetBytes([int64]0).CopyTo($Bytes, $EntryOffset + 8)
      [BitConverter]::GetBytes([int64]0).CopyTo($Bytes, $EntryOffset + 16)
      $Bytes[$EntryOffset + 24] = 1
      $NameBytes = [Text.Encoding]::UTF8.GetBytes($Name)
      $Bytes[$EntryOffset + 25] = [byte]$NameBytes.Length
      $NameBytes.CopyTo($Bytes, $EntryOffset + 26)
      $EntryOffset += 26 + $NameBytes.Length
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)
    return $Path
  }

  function New-SquirrelNuspecZipFixture {
    param (
      [string]$Name = 'SyntheticPackage'
    )

    $Path = Join-Path $TestDrive "$Name.zip"
    $Stream = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    $Archive = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
      $Entry = $Archive.CreateEntry("$Name.nuspec")
      $Writer = [IO.StreamWriter]::new($Entry.Open(), [Text.UTF8Encoding]::new($false))
      try {
        $Writer.Write("<?xml version=`"1.0`"?><package><metadata><id>$Name</id><version>1.2.3</version><title>$Name</title><authors>Example Publisher</authors></metadata></package>")
      } finally {
        $Writer.Dispose()
      }
    } finally {
      $Archive.Dispose()
      $Stream.Dispose()
    }

    return $Path
  }
}

Describe 'Squirrel parser' {
  It 'Should reject a .NET app bundle that contains Squirrel libraries without package metadata' {
    $Fixture = New-SquirrelLibraryBundleFixture
    { Get-SquirrelInfo -Path $Fixture } | Should -Throw '*contains Squirrel libraries but no embedded nupkg*'
    Test-SquirrelInstaller -Path $Fixture | Should -BeFalse
  }

  It 'Should convert Squirrel RELEASES feed content without fetching it' {
    $Releases = @'
0123456789abcdef0123456789abcdef01234567 https://updates.example.test/win/App-1.2.3-full.nupkg?token=dynamic 12345 # 50%
89abcdef0123456789abcdef0123456789abcdef App-1.2.2-delta.nupkg 2345
'@
    $Entries = $Releases | ConvertFrom-SquirrelReleases

    $Entries | Should -HaveCount 2
    $Entries[0].Version | Should -Be '1.2.3'
    $Entries[0].Sha1 | Should -Be '0123456789abcdef0123456789abcdef01234567'
    $Entries[0].Filename | Should -Be 'App-1.2.3-full.nupkg'
    $Entries[0].Filesize | Should -Be 12345
    $Entries[0].IsDelta | Should -BeFalse
    $Entries[0].BaseUrl | Should -Be 'https://updates.example.test/win/'
    $Entries[0].Query | Should -Be '?token=dynamic'
    $Entries[0].StagingPercentage | Should -Be 0.5
    $Entries[1].IsDelta | Should -BeTrue
  }

  It 'Should retain package metadata but omit launcher policy for generic ZIP evidence' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'GenericPackage'

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)

      Mock Get-PEDotNetBundleInfo { $null }
      Mock Get-SquirrelPeResourceZipCandidate { @() }
      Mock Get-SquirrelBundleHeader { $null }
      Mock Get-SquirrelZipLocalHeaderOffset { @(0L) }

      $Info = Get-SquirrelInfo -Path $Fixture

      $Info.Family | Should -Be 'Squirrel/Velopack'
      $Info.InstallerType | Should -Be 'exe'
      $Info.Confidence | Should -Be 'low'
      $Info.DetectionRoute | Should -Be 'EmbeddedZipFallback'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.PackageId | Should -Be 'GenericPackage'
      $Info.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'
      $Info.InstallModes | Should -BeNullOrEmpty
      $Info.InstallerSwitches.Count | Should -Be 0
      $Info.UnresolvedFields | Should -Contain 'InstallerSwitches'
    }
  }

  It 'Should omit launcher policy when authoritative Squirrel and Velopack routes conflict' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'ConflictingPackage'
    $Length = (Get-Item -LiteralPath $Fixture).Length

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture; Length = $Length } {
      param($Fixture, $Length)

      Mock Get-PEDotNetBundleInfo { $null }
      Mock Get-SquirrelPeResourceZipCandidate { @([pscustomobject]@{ Offset = 0L; Length = $Length }) }
      Mock Get-SquirrelBundleHeader { [pscustomobject]@{ Offset = 0L; Length = $Length } }

      $Info = Get-SquirrelInfo -Path $Fixture

      $Info.Family | Should -Be 'Squirrel/Velopack'
      $Info.DetectionRoute | Should -Be 'ConflictingAuthoritativeRoutes'
      $Info.DetectionEvidence.Kind | Should -Contain 'PEResource'
      $Info.DetectionEvidence.Kind | Should -Contain 'BundleLocator'
      $Info.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'
      $Info.InstallerSwitches.Count | Should -Be 0
      $Info.Diagnostics.Message | Should -Match 'validates both'
    }
  }

  It 'Should reject a Velopack locator whose payload range exceeds the file' {
    $Fixture = Join-Path $TestDrive 'MalformedVelopack.exe'
    $Bytes = [byte[]]::new(256)
    [BitConverter]::GetBytes([int64]128).CopyTo($Bytes, 64)
    [BitConverter]::GetBytes([int64]1024).CopyTo($Bytes, 72)
    [byte[]]$Signature = 0x94, 0xF0, 0xB1, 0x7B, 0x68, 0x93, 0xE0, 0x29, 0x37, 0xEB, 0x34, 0xEF, 0x53, 0xAA, 0xE7, 0xD4, 0x2B, 0x54, 0xF5, 0x70, 0x7E, 0xF5, 0xD6, 0xF5, 0x78, 0x54, 0x98, 0x3E, 0x5E, 0x94, 0xED, 0x7D
    $Signature.CopyTo($Bytes, 80)
    [IO.File]::WriteAllBytes($Fixture, $Bytes)

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)
      Get-SquirrelBundleHeader -Path $Fixture | Should -BeNullOrEmpty
    }
  }

  It 'Should read nested nupkg metadata from the Sourcetree installer' {
    $Fixture = Get-InstallerFixture -Name 'SourceTreeSetup-3.4.31.exe' -Url 'https://product-downloads.atlassian.com/software/sourcetree/windows/ga/SourceTreeSetup-3.4.31.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Squirrel'
    $Info.Confidence | Should -Be 'high'
    $Info.DetectionRoute | Should -Be 'SquirrelPeResource'
    $Info.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'
    $Info.InstallerSwitches.Silent | Should -Be '--silent'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '--silent'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
    $Info.ProductCode | Should -Be 'SourceTree'
    $Info.DisplayName | Should -Be 'SourceTree'
    $Info.DisplayVersion | Should -Be '3.4.31'
    $Info.Publisher | Should -Be 'Atlassian'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'SourceTree-3.4.31-full.nupkg'
  }

  It 'Should read nested nupkg metadata from the Dialpad installer' {
    $Fixture = Get-InstallerFixture -Name 'DialpadSetup-2605.1.0_x64.exe' -Url 'https://storage.googleapis.com/dialpad_native/stable/win32/x64/DialpadSetup-2605.1.0_x64.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'dialpad'
    $Info.DisplayName | Should -Be 'Dialpad'
    $Info.DisplayVersion | Should -Be '2605.1.0'
    $Info.Publisher | Should -Be 'Dialpad'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'dialpad-2605.1.0-full.nupkg'
  }

  It 'Should read direct nuspec metadata from the Appeee installer' {
    $Fixture = Get-InstallerFixture -Name 'AppeeeSetup.exe' -Url 'https://web.appeee.nl/Files/UpdateWinApp/appeee/AppeeeSetup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Velopack'
    $Info.Confidence | Should -Be 'high'
    $Info.DetectionRoute | Should -Be 'VelopackBundle'
    $Info.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'
    $Info.InstallerSwitches.Silent | Should -Be '--silent'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '--silent'
    $Info.InstallerSwitches.InstallLocation | Should -Be '--installto "<INSTALLPATH>"'
    $Info.InstallerSwitches.Log | Should -Be '--log "<LOGPATH>"'
    $Info.ProductCode | Should -Be 'Appeee'
    $Info.DisplayName | Should -Be 'Appeee'
    $Info.DisplayVersion | Should -Be '2.0.0'
    $Info.Publisher | Should -Be 'Appeee'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -BeNullOrEmpty
  }

  It 'Should read resource nupkg metadata from the Amazon Chime installer' {
    $Fixture = Get-InstallerFixture -Name 'Chime-5.23.32138.exe' -Url 'https://clients.chime.aws/win-nme/Chime-5.23.32138.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'AmazonChime'
    $Info.DisplayName | Should -Be 'Amazon Chime'
    $Info.DisplayVersion | Should -Be '5.23.32138'
    $Info.Publisher | Should -Be 'Amazon.com Services LLC'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'AmazonChime-5.23.32138-full.nupkg'
  }

  It 'Should read resource nupkg metadata from the Toggl Track installer' {
    $Fixture = Get-InstallerFixture -Name 'TogglTrack-windows64.exe' -Url 'https://toggl.com/track/toggl-desktop/downloads/windows/stable/TogglTrack-windows64.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'TogglTrack'
    $Info.DisplayName | Should -Be 'Toggl Track'
    $Info.DisplayVersion | Should -Match '^\d+\.\d+\.\d+$'
    $Info.Publisher | Should -Be 'Toggl OÜ'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be "TogglTrack-$($Info.DisplayVersion)-full.nupkg"
  }

  It 'Should read nested nupkg metadata from the Slack installer' {
    $Fixture = Get-InstallerFixture -Name 'SlackSetup-4.50.143.exe' -Url 'https://downloads.slack-edge.com/desktop-releases/windows/x64/4.50.143/SlackSetup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'slack'
    $Info.DisplayName | Should -Be 'Slack'
    $Info.DisplayVersion | Should -Be '4.50.143'
    $Info.Publisher | Should -Be 'Slack Technologies Inc.'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'slack-4.50.143-full.nupkg'
  }

  It 'Should read nested nupkg metadata from the Figma installer' {
    $Fixture = Get-InstallerFixture -Name 'Figma-126.6.12.exe' -Url 'https://desktop.figma.com/win/build/Figma-126.6.12.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'Figma'
    $Info.DisplayName | Should -Be 'Figma'
    $Info.DisplayVersion | Should -Be '126.6.12'
    $Info.Publisher | Should -Be 'Figma, Inc.'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'Figma-126.6.12-full.nupkg'
  }

  It 'Should read nested nupkg metadata from the Discord installer' {
    $Fixture = Get-InstallerFixture -Name 'DiscordSetup-1.0.9244.exe' -Url 'https://dl.discordapp.net/distro/app/stable/win/x64/1.0.9244/DiscordSetup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'Discord'
    $Info.DisplayName | Should -Be 'Discord'
    $Info.DisplayVersion | Should -Be '1.0.9244'
    $Info.Publisher | Should -Be 'Discord Inc.'
    $Info.Scope | Should -Be 'user'
    $Info.DefaultInstallLocation | Should -Be '%LocalAppData%\Discord'
    $Info.NupkgPath | Should -Be 'Discord-1.0.9244-full.nupkg'
  }

  It 'Should keep the Tower Velopack EXE identity separate from its MSI ARP prefix' {
    $Fixture = Get-InstallerFixture -Name 'Tower-13.1.576.exe' -Url 'https://www.git-tower.com/apps/tower3-win/576-01812649/Tower-13.1.576.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.Family | Should -Be 'Velopack'
    $Info.InstallerType | Should -Be 'exe'
    $Info.DetectionRoute | Should -Be 'VelopackBundle'
    $Info.InstallerSwitches.InstallLocation | Should -Be '--installto "<INSTALLPATH>"'
    $Info.ProductCode | Should -Be 'Tower'
    $Info.DisplayName | Should -Be 'Tower'
    $Info.DisplayVersion | Should -Be '13.1.576'
    $Info.Publisher | Should -Be 'saas.group'
  }
}
