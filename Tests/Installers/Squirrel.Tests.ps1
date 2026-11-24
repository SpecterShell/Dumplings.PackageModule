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
      [string]$Name = 'SyntheticPackage',
      [string]$AdditionalMetadata = '',
      [string]$NuspecXml
    )

    $Path = Join-Path $TestDrive "$Name.zip"
    $Stream = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    $Archive = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
      $Entry = $Archive.CreateEntry("$Name.nuspec")
      $Writer = [IO.StreamWriter]::new($Entry.Open(), [Text.UTF8Encoding]::new($false))
      try {
        $Content = if ($PSBoundParameters.ContainsKey('NuspecXml')) { $NuspecXml } else { "<?xml version=`"1.0`"?><package><metadata><id>$Name</id><version>1.2.3</version><title>$Name</title><authors>Example Publisher</authors>$AdditionalMetadata</metadata></package>" }
        $Writer.Write($Content)
      } finally {
        $Writer.Dispose()
      }
    } finally {
      $Archive.Dispose()
      $Stream.Dispose()
    }

    return $Path
  }

  function Get-SquirrelFixtureArchiveEntryName {
    param (
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)][int]$ResourceId,
      [string]$NestedEntryName
    )

    $Resource = @(Get-PEResourceInfo -Path $Path | Where-Object { $_.TypeName -eq 'DATA' -and $_.Id -eq $ResourceId })
    if ($Resource.Count -ne 1) { throw "Expected exactly one DATA/#$ResourceId resource in $Path." }
    $Stream = [IO.File]::OpenRead($Path)
    $Range = $null
    $Archive = $null
    $NestedStream = $null
    $Seekable = $null
    $NestedArchive = $null
    try {
      $Range = New-BoundedReadStream -Stream $Stream -Offset $Resource[0].Offset -Length $Resource[0].Size -LeaveOpen
      $Archive = Get-InstallerArchive -Stream $Range
      if (-not $NestedEntryName) { return [string[]]@(Get-InstallerArchiveEntry -Archive $Archive | Select-Object -ExpandProperty FullName) }
      $NestedEntry = @(Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -eq $NestedEntryName })
      if ($NestedEntry.Count -ne 1) { throw "Expected exactly one '$NestedEntryName' entry in DATA/#$ResourceId." }
      $NestedStream = Open-InstallerArchiveEntry -Entry $NestedEntry[0]
      $Seekable = New-InstallerSeekableStream -SourceStream $NestedStream -MaximumBytes 1073741824 -MemoryThresholdBytes 16777216
      $NestedArchive = Get-InstallerArchive -Stream $Seekable.Stream
      return [string[]]@(Get-InstallerArchiveEntry -Archive $NestedArchive | Select-Object -ExpandProperty FullName)
    } finally {
      if ($NestedArchive) { $NestedArchive.Dispose() }
      if ($Seekable) { $Seekable.Dispose() }
      if ($NestedStream) { $NestedStream.Dispose() }
      if ($Archive) { $Archive.Dispose() }
      if ($Range) { $Range.Dispose() }
      $Stream.Dispose()
    }
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

  It 'Should reject DTD declarations in package metadata' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'UnsafePackage' -NuspecXml '<!DOCTYPE package [<!ENTITY external SYSTEM "file:///C:/Windows/win.ini">]><package><metadata><id>&external;</id><version>1.2.3</version></metadata></package>'
    $Archive = Get-InstallerArchive -Path $Fixture
    try {
      InModuleScope Squirrel -Parameters @{ Archive = $Archive } {
        param($Archive)
        { Read-SquirrelNuspecFromZipArchive -Archive $Archive } | Should -Throw '*DTD*'
      }
    } finally {
      $Archive.Dispose()
    }
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
      $Info.UnresolvedFields | Should -Contain 'LauncherGeneration'
      $Info.Diagnostics.Id | Should -Contain 'Squirrel.Detection.GenericPackageOnly'
    }
  }

  It 'Should omit launcher policy when authoritative Squirrel and Velopack routes conflict' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'ConflictingPackage'
    $Length = (Get-Item -LiteralPath $Fixture).Length

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture; Length = $Length } {
      param($Fixture, $Length)

      Mock Get-PELayout { [pscustomobject]@{ NativeLayout = [pscustomobject]@{} } }
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
      $Info.Diagnostics.Message | Should -Match 'validates multiple'
      $Info.Diagnostics.Id | Should -Contain 'Squirrel.Detection.AuthoritativeRouteConflict'
    }
  }

  It 'Should reject multiple top-level nuspec identities' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'DuplicateNuspec'
    $Stream = [IO.File]::Open($Fixture, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    $Archive = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Update, $false)
    try {
      $Entry = $Archive.CreateEntry('Second.nuspec')
      $Writer = [IO.StreamWriter]::new($Entry.Open(), [Text.UTF8Encoding]::new($false))
      try { $Writer.Write('<package><metadata><id>Second</id><version>1.0.0</version></metadata></package>') } finally { $Writer.Dispose() }
    } finally {
      $Archive.Dispose()
      $Stream.Dispose()
    }

    $Archive = Get-InstallerArchive -Path $Fixture
    try {
      InModuleScope Squirrel -Parameters @{ Archive = $Archive } {
        param($Archive)
        { Read-SquirrelNuspecFromZipArchive -Archive $Archive } | Should -Throw '*multiple top-level nuspec*'
      }
    } finally {
      $Archive.Dispose()
    }
  }

  It 'Should retain only common launcher behavior when Clowd and Rust Velopack routes conflict' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'SameFamilyConflict' -AdditionalMetadata '<mainExe>SameFamilyConflict.exe</mainExe><machineArchitecture>x64</machineArchitecture><rid>win-x64</rid>'
    $Length = (Get-Item -LiteralPath $Fixture).Length

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture; Length = $Length } {
      param($Fixture, $Length)

      Mock Get-PELayout { [pscustomobject]@{ NativeLayout = [pscustomobject]@{} } }
      Mock Get-PEDotNetBundleInfo { $null }
      Mock Get-SquirrelPeResourceZipCandidate {
        @([pscustomobject]@{
            Offset = 0L; Length = $Length; Family = 'Velopack'; DetectionRoute = 'ClowdSquirrelPeResource'
            LauncherGeneration = 'Clowd.Squirrel.Resource'; LauncherCapabilities = [pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false }
            ResourceId = 205; ResourceLanguageId = 1033; ResourceMetadata = $null
          })
      }
      Mock Get-SquirrelBundleHeader {
        [pscustomobject]@{
          Offset = 0L; Length = $Length; SignatureOffset = 64L; LauncherGeneration = 'Velopack'
          LauncherCapabilities = [pscustomobject]@{ Silent = $true; InstallLocation = $true; Log = $true }
        }
      }
      Mock Get-SquirrelMainExecutableEvidence { [pscustomobject]@{ Architecture = 'x64'; ImportedDlls = @(); DependencyDllNames = @(); TargetFramework = $null } }

      $Info = Get-SquirrelInfo -Path $Fixture

      $Info.Family | Should -Be 'Velopack'
      $Info.ProductCode | Should -Be 'SameFamilyConflict'
      $Info.LauncherGeneration | Should -BeNullOrEmpty
      $Info.InstallerSwitches.Silent | Should -Be '--silent'
      $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
      $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Log'
      $Info.UnresolvedFields | Should -Contain 'LauncherGeneration'
      $Info.UnresolvedFields | Should -Contain 'InstallerSwitches'
      $Info.Diagnostics.Id | Should -Contain 'Squirrel.Detection.AuthoritativeRouteConflict'
      $Info.PayloadArchitectures | Should -Be @('x64')
    }
  }

  It 'Should reject authoritative routes with the same identity but conflicting package metadata' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'MetadataConflict'
    $Length = (Get-Item -LiteralPath $Fixture).Length

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture; Length = $Length } {
      param($Fixture, $Length)
      Mock Get-PELayout { [pscustomobject]@{ NativeLayout = [pscustomobject]@{} } }
      Mock Get-PEDotNetBundleInfo { $null }
      Mock Get-SquirrelPeResourceZipCandidate {
        @([pscustomobject]@{ Offset = 0L; Length = $Length; Family = 'Velopack'; DetectionRoute = 'ClowdSquirrelPeResource'; LauncherGeneration = 'Clowd.Squirrel.Resource'; ResourceId = 205 })
      }
      Mock Get-SquirrelBundleHeader { [pscustomobject]@{ Offset = 0L; Length = $Length; SignatureOffset = 64L; LauncherGeneration = 'Clowd.Squirrel.Bundle' } }
      Mock Get-SquirrelInfoFromZipCandidate {
        $Title = $DetectionRoute -eq 'VelopackBundle' ? 'Bundle Title' : 'Resource Title'
        [pscustomobject]@{
          Family = 'Velopack'; ProductCode = 'MetadataConflict'; DisplayVersion = '1.2.3'; DetectionRoute = $DetectionRoute
          LauncherGeneration = $LauncherGeneration; LauncherCapabilities = [pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false }
          Nuspec = [pscustomobject]@{ Id = 'MetadataConflict'; Title = $Title; Version = '1.2.3'; Authors = 'Example' }
        }
      }

      { Get-SquirrelInfo -Path $Fixture } | Should -Throw '*conflicting authoritative Squirrel-family package metadata*'
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

  It 'Should reject a signed locator that points backward into the launcher' {
    $Fixture = Join-Path $TestDrive 'BackwardVelopack.exe'
    $Bytes = [byte[]]::new(256)
    [BitConverter]::GetBytes([int64]32).CopyTo($Bytes, 64)
    [BitConverter]::GetBytes([int64]16).CopyTo($Bytes, 72)
    [byte[]]$Signature = 0x94, 0xF0, 0xB1, 0x7B, 0x68, 0x93, 0xE0, 0x29, 0x37, 0xEB, 0x34, 0xEF, 0x53, 0xAA, 0xE7, 0xD4, 0x2B, 0x54, 0xF5, 0x70, 0x7E, 0xF5, 0xD6, 0xF5, 0x78, 0x54, 0x98, 0x3E, 0x5E, 0x94, 0xED, 0x7D
    $Signature.CopyTo($Bytes, 80)
    [IO.File]::WriteAllBytes($Fixture, $Bytes)

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)
      Get-SquirrelBundleHeader -Path $Fixture | Should -BeNullOrEmpty
    }
  }

  It 'Should reject the zero-version sentinel for a Rust Velopack package' {
    InModuleScope Squirrel {
      $Nuspec = [pscustomobject]@{ Id = 'ZeroVersion'; Version = '0.0.0'; MainExecutable = 'ZeroVersion.exe' }
      { Assert-SquirrelNuspecMetadata -Nuspec $Nuspec -LauncherGeneration 'Velopack' } | Should -Throw '*invalid version*'
    }
  }

  It 'Should not downgrade a malformed authoritative route to generic ZIP evidence' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'MalformedAuthoritative'
    $Length = (Get-Item -LiteralPath $Fixture).Length

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture; Length = $Length } {
      param($Fixture, $Length)
      Mock Get-PELayout { $null }
      Mock Get-PEDotNetBundleInfo { $null }
      Mock Get-SquirrelPeResourceZipCandidate { @() }
      Mock Get-SquirrelBundleHeader { [pscustomobject]@{ Offset = 1L; Length = $Length - 1; SignatureOffset = 64L } }
      { Get-SquirrelInfo -Path $Fixture } | Should -Throw '*VelopackBundle at offset 1*'
    }
  }

  It 'Should not downgrade malformed authoritative PE-resource evidence to generic ZIP evidence' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'MalformedResourceAuthoritative'

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)
      Mock Get-PELayout { [pscustomobject]@{ NativeLayout = [pscustomobject]@{} } }
      Mock Get-PEDotNetBundleInfo { $null }
      Mock Get-SquirrelPeResourceZipCandidate { throw 'invalid DATA/#205 metadata' }
      Mock Get-SquirrelBundleHeader { $null }
      Mock Get-SquirrelZipLocalHeaderOffset { @(0L) }

      { Get-SquirrelInfo -Path $Fixture } | Should -Throw '*Squirrel PE-resource inspection failed*invalid DATA/#205 metadata*'
      Should -Invoke Get-SquirrelZipLocalHeaderOffset -Times 0 -Exactly
    }
  }

  It 'Should reject Rust Velopack versions whose numeric components exceed UInt64' {
    InModuleScope Squirrel {
      $Nuspec = [pscustomobject]@{ Id = 'HugeVersion'; Version = '18446744073709551616.1.0'; MainExecutable = 'HugeVersion.exe' }
      { Assert-SquirrelNuspecMetadata -Nuspec $Nuspec -LauncherGeneration 'Velopack' } | Should -Throw '*invalid version*'
    }
  }

  It 'Should reject unsafe or non-executable Rust Velopack mainExe values' -ForEach @(
    @{ MainExecutable = '..\Escape.exe' }
    @{ MainExecutable = 'C:\Absolute.exe' }
    @{ MainExecutable = '/rooted.exe' }
    @{ MainExecutable = 'not-an-executable.dll' }
    @{ MainExecutable = 'folder//empty.exe' }
    @{ MainExecutable = 'folder.\App.exe' }
    @{ MainExecutable = 'CON.exe' }
  ) {
    InModuleScope Squirrel -Parameters @{ MainExecutable = $MainExecutable } {
      param($MainExecutable)
      $Nuspec = [pscustomobject]@{ Id = 'UnsafeMainExe'; Version = '1.2.3'; MainExecutable = $MainExecutable }
      { Assert-SquirrelNuspecMetadata -Nuspec $Nuspec -LauncherGeneration 'Velopack' } | Should -Throw '*unsafe or invalid mainExe*'
    }
  }

  It 'Should accept a relative Rust Velopack mainExe in a subdirectory' {
    InModuleScope Squirrel {
      $Nuspec = [pscustomobject]@{ Id = 'NestedMainExe'; Version = '1.2.3'; MainExecutable = 'tools/NestedMainExe.exe' }
      { Assert-SquirrelNuspecMetadata -Nuspec $Nuspec -LauncherGeneration 'Velopack' } | Should -Not -Throw
    }
  }

  It 'Should reject a package that omits its declared main executable entry' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'MissingMainExe' -AdditionalMetadata '<mainExe>MissingMainExe.exe</mainExe>'
    $Archive = Get-InstallerArchive -Path $Fixture
    try {
      InModuleScope Squirrel -Parameters @{ Archive = $Archive } {
        param($Archive)
        { Get-SquirrelMainExecutableEvidence -Archive $Archive -MainExecutable 'MissingMainExe.exe' } | Should -Throw '*does not contain its declared main executable*'
      }
    } finally {
      $Archive.Dispose()
    }
  }

  It 'Should not treat an application payload nupkg as the classic outer package' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'PayloadNupkg' -AdditionalMetadata '<mainExe>PayloadNupkg.exe</mainExe>'
    $Stream = [IO.File]::Open($Fixture, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    $Archive = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Update, $false)
    try {
      $Entry = $Archive.CreateEntry('lib/app/cache.nupkg')
      $Entry.Open().Dispose()
    } finally {
      $Archive.Dispose()
      $Stream.Dispose()
    }

    $Length = (Get-Item -LiteralPath $Fixture).Length
    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture; Length = $Length } {
      param($Fixture, $Length)
      Mock Get-SquirrelMainExecutableEvidence { [pscustomobject]@{ Architecture = 'x64'; ImportedDlls = @(); DependencyDllNames = @(); InspectionWarnings = @() } }
      $InputStream = [IO.File]::OpenRead($Fixture)
      try {
        $Info = Get-SquirrelInfoFromZipCandidate -Path $Fixture -Stream $InputStream -Offset 0 -Length $Length -Family Velopack -DetectionRoute VelopackBundle -Confidence high -LauncherGeneration Velopack
        $Info.ProductCode | Should -Be 'PayloadNupkg'
        $Info.NupkgPath | Should -BeNullOrEmpty
      } finally {
        $InputStream.Dispose()
      }
    }
  }

  It 'Should report conflicting machineArchitecture, RID, and payload PE evidence' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'ArchitectureConflict'
    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)
      $Nuspec = [pscustomobject]@{
        Id = 'ArchitectureConflict'; Title = 'Architecture Conflict'; Version = '1.2.3'; Authors = 'Example'
        MachineArchitecture = 'x64'; Rid = 'win-arm64'; MainExecutable = 'ArchitectureConflict.exe'; OperatingSystem = 'linux'
      }
      $PayloadEvidence = [pscustomobject]@{ Architecture = 'x64'; ImportedDlls = @(); DependencyDllNames = @(); TargetFramework = $null }
      $Info = ConvertTo-SquirrelInfo -Path $Fixture -Family Velopack -DetectionRoute VelopackBundle -Confidence high -ZipOffset 0 -Nuspec $Nuspec -LauncherGeneration Velopack -LauncherCapabilities ([pscustomobject]@{ Silent = $true; InstallLocation = $true; Log = $true }) -PayloadEvidence $PayloadEvidence

      $Info.Architecture | Should -BeNullOrEmpty
      $Info.PackageOperatingSystem | Should -BeNullOrEmpty
      $Info.PackageOperatingSystemRaw | Should -Be 'linux'
      $Info.UnresolvedFields | Should -Contain 'Architecture'
      $Info.PayloadArchitectures | Should -BeNullOrEmpty
      $Info.Diagnostics.Id | Should -Contain 'Squirrel.Metadata.ArchitectureConflict'
      $Info.Diagnostics.Id | Should -Contain 'Squirrel.Metadata.NonWindowsOperatingSystem'
    }
  }

  It 'Should emit stable diagnostics for unsupported architecture and invalid minimum OS metadata' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'InvalidMetadata'
    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)
      $Nuspec = [pscustomobject]@{
        Id = 'InvalidMetadata'; Title = 'Invalid Metadata'; Version = '1.2.3'; Authors = 'Example'
        MachineArchitecture = 'mips64'; MinimumOSVersion = 'Windows 10'
      }
      $Info = ConvertTo-SquirrelInfo -Path $Fixture -Family Velopack -DetectionRoute VelopackBundle -Confidence high -ZipOffset 0 -Nuspec $Nuspec -LauncherGeneration 'Clowd.Squirrel.Bundle' -LauncherCapabilities ([pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false })

      $Info.Architecture | Should -BeNullOrEmpty
      $Info.MinimumOSVersion | Should -BeNullOrEmpty
      $Info.Diagnostics.Id | Should -Contain 'Squirrel.Metadata.UnsupportedMachineArchitecture'
      $Info.Diagnostics.Id | Should -Contain 'Squirrel.Metadata.InvalidMinimumOSVersion'
    }
  }

  It 'Should allow the signed locator scan count to be raised for decoy-heavy launchers' {
    $Fixture = Join-Path $TestDrive 'ManyLocatorMarkers.exe'
    $Bytes = [byte[]]::new(4097)
    [byte[]]$Signature = 0x94, 0xF0, 0xB1, 0x7B, 0x68, 0x93, 0xE0, 0x29, 0x37, 0xEB, 0x34, 0xEF, 0x53, 0xAA, 0xE7, 0xD4, 0x2B, 0x54, 0xF5, 0x70, 0x7E, 0xF5, 0xD6, 0xF5, 0x78, 0x54, 0x98, 0x3E, 0x5E, 0x94, 0xED, 0x7D
    foreach ($Index in 0..8) {
      $SignatureOffset = 128 + ($Index * 96)
      [BitConverter]::GetBytes([int64]32).CopyTo($Bytes, $SignatureOffset - 16)
      [BitConverter]::GetBytes([int64]1).CopyTo($Bytes, $SignatureOffset - 8)
      $Signature.CopyTo($Bytes, $SignatureOffset)
    }
    $ValidSignatureOffset = 1024
    [BitConverter]::GetBytes([int64]4096).CopyTo($Bytes, $ValidSignatureOffset - 16)
    [BitConverter]::GetBytes([int64]1).CopyTo($Bytes, $ValidSignatureOffset - 8)
    $Signature.CopyTo($Bytes, $ValidSignatureOffset)
    [IO.File]::WriteAllBytes($Fixture, $Bytes)

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)
      Get-SquirrelBundleHeader -Path $Fixture | Should -BeNullOrEmpty
      $Header = Get-SquirrelBundleHeader -Path $Fixture -MaximumSignatures 16
      $Header.Offset | Should -Be 4096
      $Header.SignatureOffset | Should -Be 1024
      $Stream = [IO.File]::OpenRead($Fixture)
      try {
        $Stream.Position = 37
        $null = Get-SquirrelBundleHeader -Stream $Stream -MaximumSignatures 16
        $Stream.Position | Should -Be 37
      } finally {
        $Stream.Dispose()
      }
    }
  }

  It 'Should ignore an in-range decoy locator and validate a later Velopack package' {
    $Package = New-SquirrelNuspecZipFixture -Name 'LocatorPackage' -AdditionalMetadata '<machineArchitecture>arm64</machineArchitecture><os>WiNdOwS</os><osMinVersion>10.0.19041.0</osMinVersion><mainExe>LocatorPackage.exe</mainExe><rid>win-arm64</rid><channel>stable</channel><runtimeDependencies>vcredist143-x64;net8-x64-desktop</runtimeDependencies><shortcutLocations>Desktop,StartMenuRoot</shortcutLocations><shortcutAmuid>velopack.LocatorPackage</shortcutAmuid><releaseNotes>Release notes</releaseNotes><releaseNotesHtml><![CDATA[<p>Release notes</p>]]></releaseNotesHtml><splashProgressColor>#123456</splashProgressColor>'
    $PackageBytes = [IO.File]::ReadAllBytes($Package)
    $Fixture = Join-Path $TestDrive 'DecoyVelopack.exe'
    $Bytes = [byte[]]::new(512 + $PackageBytes.Length)
    [Text.Encoding]::UTF8.GetBytes('VELOPACK_FIRSTRUN').CopyTo($Bytes, 256)
    [Text.Encoding]::UTF8.GetBytes('installtoDIR').CopyTo($Bytes, 288)
    [Text.Encoding]::UTF8.GetBytes('logFILE').CopyTo($Bytes, 320)
    [BitConverter]::GetBytes([int64]400).CopyTo($Bytes, 64)
    [BitConverter]::GetBytes([int64]16).CopyTo($Bytes, 72)
    [BitConverter]::GetBytes([int64]512).CopyTo($Bytes, 176)
    [BitConverter]::GetBytes([int64]$PackageBytes.Length).CopyTo($Bytes, 184)
    [byte[]]$Signature = 0x94, 0xF0, 0xB1, 0x7B, 0x68, 0x93, 0xE0, 0x29, 0x37, 0xEB, 0x34, 0xEF, 0x53, 0xAA, 0xE7, 0xD4, 0x2B, 0x54, 0xF5, 0x70, 0x7E, 0xF5, 0xD6, 0xF5, 0x78, 0x54, 0x98, 0x3E, 0x5E, 0x94, 0xED, 0x7D
    $Signature.CopyTo($Bytes, 80)
    $Signature.CopyTo($Bytes, 192)
    $PackageBytes.CopyTo($Bytes, 512)
    [IO.File]::WriteAllBytes($Fixture, $Bytes)

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)

      Mock Get-PELayout { $null }
      Mock Get-PEDotNetBundleInfo { $null }
      Mock Get-SquirrelPeResourceZipCandidate { @() }
      Mock Get-SquirrelMainExecutableEvidence { [pscustomobject]@{ Architecture = 'arm64'; ImportedDlls = @(); DependencyDllNames = @(); TargetFramework = $null } }

      $Info = Get-SquirrelInfo -Path $Fixture
      $Info.Family | Should -Be 'Velopack'
      $Info.ProductCode | Should -Be 'LocatorPackage'
      $Info.DetectionEvidence.SignatureOffset | Should -Be 192
      $Info.LauncherGeneration | Should -Be 'Velopack'
      $Info.InstallerSwitches.InstallLocation | Should -Be '--installto "<INSTALLPATH>"'
      $Info.InstallerSwitches.Log | Should -Be '--log "<LOGPATH>"'
      $Info.Architecture | Should -Be 'arm64'
      $Info.PackageOperatingSystem | Should -Be 'windows'
      $Info.MinimumOSVersion | Should -Be '10.0.19041.0'
      $Info.MainExecutable | Should -Be 'LocatorPackage.exe'
      $Info.PackageRid | Should -Be 'win-arm64'
      $Info.Channel | Should -Be 'stable'
      $Info.RuntimeDependencies | Should -Be @('vcredist143-x64', 'net8-x64-desktop')
      $Info.RuntimeDependenciesRaw | Should -Be 'vcredist143-x64;net8-x64-desktop'
      $Info.ShortcutLocations | Should -Be @('Desktop', 'StartMenuRoot')
      $Info.ShortcutLocationsRaw | Should -Be 'Desktop,StartMenuRoot'
      $Info.ShortcutAumid | Should -Be 'velopack.LocatorPackage'
      $Info.ReleaseNotes | Should -Be 'Release notes'
      $Info.ReleaseNotesHtml | Should -Be '<p>Release notes</p>'
      $Info.SplashProgressColor | Should -Be '#123456'
    }
  }

  It 'Should treat Clowd.Squirrel DATA 205 as an authoritative legacy package resource' {
    $Package = New-SquirrelNuspecZipFixture -Name 'ClowdResourcePackage'
    $PackageBytes = [IO.File]::ReadAllBytes($Package)
    $PackageOffset = 1024
    $Fixture = Join-Path $TestDrive 'ClowdResourceSetup.exe'
    $Bytes = [byte[]]::new($PackageOffset + $PackageBytes.Length)
    $Resources = [Collections.Generic.List[object]]::new()
    $Metadata = @(
      @{ Id = 200; Offset = 32; Value = 'wrong-language'; LanguageId = 1041 }
      @{ Id = 200; Offset = 96; Value = 'clowdresourcepackage'; LanguageId = 1033 }
      @{ Id = 201; Offset = 192; Value = 'Clowd Resource Package'; LanguageId = 1033 }
      @{ Id = 203; Offset = 320; Value = 'net6.0, net48'; LanguageId = 1033 }
      @{ Id = 204; Offset = 448; Value = 'ClowdResourcePackage-1.2.3-full.nupkg'; LanguageId = 1033 }
    )
    foreach ($Entry in $Metadata) {
      $ValueBytes = [Text.Encoding]::Unicode.GetBytes("$($Entry.Value)`0`0")
      $ValueBytes.CopyTo($Bytes, $Entry.Offset)
      $Resources.Add([pscustomobject]@{ TypeName = 'DATA'; Id = $Entry.Id; LanguageId = $Entry.LanguageId; Size = $ValueBytes.Length; Offset = [long]$Entry.Offset })
    }
    $PackageBytes.CopyTo($Bytes, $PackageOffset)
    $Resources.Add([pscustomobject]@{ TypeName = 'DATA'; Id = 205; LanguageId = 1033; Size = $PackageBytes.Length; Offset = [long]$PackageOffset })
    [IO.File]::WriteAllBytes($Fixture, $Bytes)

    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture; Resources = $Resources } {
      param($Fixture, $Resources)

      Mock Get-PELayout { [pscustomobject]@{ NativeLayout = [pscustomobject]@{} } }
      Mock Get-PEDotNetBundleInfo { [pscustomobject]@{ Entries = @([pscustomobject]@{ RelativePath = 'Squirrel.dll' }) } }
      Mock Get-PEResourceInfo { $Resources }
      Mock Get-SquirrelBundleHeader { @() }

      $PathCandidates = @(Get-SquirrelPeResourceZipCandidate -Path $Fixture)
      $PathCandidates.ResourceMetadata.AppId | Should -Be 'clowdresourcepackage'
      $Stream = [IO.File]::OpenRead($Fixture)
      try {
        $Stream.Position = 23
        $null = Get-SquirrelPeResourceZipCandidate -Stream $Stream
        $Stream.Position | Should -Be 23
      } finally {
        $Stream.Dispose()
      }
      $Info = Get-SquirrelInfo -Path $Fixture
      $Info.Family | Should -Be 'Velopack'
      $Info.DetectionRoute | Should -Be 'ClowdSquirrelPeResource'
      $Info.DetectionEvidence.LanguageId | Should -Be 1033
      $Info.LauncherGeneration | Should -Be 'Clowd.Squirrel.Resource'
      $Info.ProductCode | Should -Be 'ClowdResourcePackage'
      $Info.InstallerSwitches.Silent | Should -Be '--silent'
      $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
      $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Log'
      $Info.ResourceMetadata.AppId | Should -Be 'clowdresourcepackage'
      $Info.ResourceMetadata.AppFriendlyName | Should -Be 'Clowd Resource Package'
      $Info.RequiredFrameworks | Should -Be @('net6.0', 'net48')
      $Info.NupkgPath | Should -Be 'ClowdResourcePackage-1.2.3-full.nupkg'
    }
  }

  It 'Should reproduce the Squirrel.Windows framework-selector fallback' {
    InModuleScope Squirrel {
      $Bytes = [Text.Encoding]::Unicode.GetBytes("futureFx`0")
      $Stream = [IO.MemoryStream]::new($Bytes, $false)
      try {
        $Metadata = Read-SquirrelWindowsResourceMetadata -Stream $Stream -Resource @(
          [pscustomobject]@{ TypeName = 'FLAGS'; Id = 132; LanguageId = 1033; Offset = 0L; Size = $Bytes.Length }
        ) -LanguageId 1033
      } finally {
        $Stream.Dispose()
      }

      $Metadata.RequiredFrameworks | Should -Be @('net45')
      $Metadata.FrameworkResourceValue | Should -Be 'futureFx'
      $Metadata.FrameworkFallbackUsed | Should -BeTrue
    }
  }

  It 'Should project generation-specific ARP metadata from package fields' {
    $Fixture = New-SquirrelNuspecZipFixture -Name 'ArpProjection'
    InModuleScope Squirrel -Parameters @{ Fixture = $Fixture } {
      param($Fixture)

      $Nuspec = [pscustomobject]@{
        Id = 'ArpProjection'; Title = ''; Version = '1.2.3-beta.4+build.7'; Authors = 'Example Publisher'; Owners = 'Example Owner'
        Description = 'Fallback display name'; Summary = 'Fallback summary'; ProjectUrl = 'https://example.test/app'; IconUrl = 'https://example.test/app.ico'
        MachineArchitecture = ''; RuntimeDependencies = ''; MainExecutable = 'ArpProjection.exe'; OperatingSystem = 'windows'; Rid = ''
        MinimumOSVersion = ''; Channel = ''; ShortcutLocations = ''; ShortcutAumid = ''; ReleaseNotes = ''; ReleaseNotesHtml = ''; SplashProgressColor = ''
      }

      $Squirrel = ConvertTo-SquirrelInfo -Path $Fixture -Family Squirrel -DetectionRoute SquirrelPeResource -Confidence high -ZipOffset 0 -Nuspec $Nuspec -LauncherGeneration 'Squirrel.Windows' -LauncherCapabilities ([pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false })
      $Squirrel.DisplayName | Should -Be 'Fallback display name'
      $Squirrel.PackageVersion | Should -Be '1.2.3-beta.4+build.7'
      $Squirrel.DisplayVersion | Should -Be '1.2.3-beta.4+build.7'
      $Squirrel.UninstallString | Should -Be '"%LocalAppData%\ArpProjection\Update.exe" --uninstall'
      $Squirrel.QuietUninstallString | Should -Be '"%LocalAppData%\ArpProjection\Update.exe" --uninstall -s'
      $Squirrel.DisplayIcon | Should -BeNullOrEmpty
      $Squirrel.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Fallback display name'
      $Squirrel.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '1.2.3-beta.4+build.7'
      $Squirrel.ArpEntries[0].URLUpdateInfo | Should -Be 'https://example.test/app'

      $Velopack = ConvertTo-SquirrelInfo -Path $Fixture -Family Velopack -DetectionRoute VelopackBundle -Confidence high -ZipOffset 0 -Nuspec $Nuspec -LauncherGeneration Velopack -LauncherCapabilities ([pscustomobject]@{ Silent = $true; InstallLocation = $true; Log = $true })
      $Velopack.DisplayName | Should -Be 'ArpProjection'
      $Velopack.PackageVersion | Should -Be '1.2.3-beta.4+build.7'
      $Velopack.DisplayVersion | Should -Be '1.2.3'
      $Velopack.QuietUninstallString | Should -Be '"%LocalAppData%\ArpProjection\Update.exe" --uninstall --silent'
      $Velopack.DisplayIcon | Should -Be '%LocalAppData%\ArpProjection\current\ArpProjection.exe'
      $Velopack.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '1.2.3'
      $Velopack.URLUpdateInfo | Should -Be 'https://example.test/app'
      $Velopack.ArpEntries[0].URLUpdateInfo | Should -BeNullOrEmpty
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
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'SourceTree'
    $Info.UninstallString | Should -Be '"%LocalAppData%\SourceTree\Update.exe" --uninstall'
    $Info.QuietUninstallString | Should -Be '"%LocalAppData%\SourceTree\Update.exe" --uninstall -s'
    $Info.LauncherGeneration | Should -Be 'Squirrel.Windows'
    $Info.RequiredFrameworks | Should -Be @('net45')
    $Info.ResourceMetadata.FrameworkResourceValue | Should -Be 'net45'
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

  It 'Should keep legacy Clowd launcher policy on the Appeee signed bundle' {
    $Fixture = Get-InstallerFixture -Name 'AppeeeSetup.exe' -Url 'https://web.appeee.nl/Files/UpdateWinApp/appeee/AppeeeSetup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.Family | Should -Be 'Velopack'
    $Info.Confidence | Should -Be 'high'
    $Info.DetectionRoute | Should -Be 'VelopackBundle'
    $Info.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'
    $Info.InstallerSwitches.Silent | Should -Be '--silent'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '--silent'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Log'
    $Info.ProductCode | Should -Be 'Appeee'
    $Info.DisplayName | Should -Be 'Appeee'
    $Info.DisplayVersion | Should -Be '2.0.0'
    $Info.Publisher | Should -Be 'Appeee'
    $Info.Scope | Should -Be 'user'
    $Info.Architecture | Should -Be 'x86'
    $Info.LauncherGeneration | Should -Be 'Clowd.Squirrel.Bundle'
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
    $Info.InstallerSwitches.Log | Should -Be '--log "<LOGPATH>"'
    $Info.ProductCode | Should -Be 'Tower'
    $Info.DisplayName | Should -Be 'Tower'
    $Info.DisplayVersion | Should -Be '13.1.576'
    $Info.Publisher | Should -Be 'saas.group'
    $Info.LauncherGeneration | Should -Be 'Velopack'
    $Info.Architecture | Should -Be 'x64'
    $Info.MainExecutable | Should -Be 'Tower.exe'
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'Tower'
    $Info.UninstallString | Should -Be '"%LocalAppData%\Tower\Update.exe" --uninstall'
    $Info.QuietUninstallString | Should -Be '"%LocalAppData%\Tower\Update.exe" --uninstall --silent'
    $Info.DisplayIcon | Should -Be '%LocalAppData%\Tower\current\Tower.exe'
    $Info.PayloadArchitectures | Should -Be @('x64')
    $Info.PayloadArchitectureInfo.RelativePath | Should -Be 'lib/app/Tower.exe'
    $Info.PayloadArchitectureInfo.MachineName | Should -Be 'AMD64'
    $Info.PayloadDependencyInfo.DllNames | Should -Contain 'KERNEL32.dll'
    $Info.PackageRid | Should -Be 'win-x64'
    $Info.Channel | Should -Be 'win'
    $Info.ShortcutAumid | Should -Be 'velopack.Tower'
  }

  It 'Should parse the controlled application-complete Squirrel.Windows 1.9.1 DATA 131 fixture' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Squirrel\Squirrel.Windows\1.9.1\ProjectWithContent-1.0.0.0-beta-Setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The controlled Squirrel.Windows 1.9.1 fixture is not cached.'
      return
    }

    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be '2D153B0DCF9DFA32C3BDD0DCD7F10E0EDB5DD06307DB339DCBB39B5FF4857FEC'
    $Info = Get-SquirrelInfo -Path $Fixture
    $OuterEntries = Get-SquirrelFixtureArchiveEntryName -Path $Fixture -ResourceId 131
    $PackageEntries = Get-SquirrelFixtureArchiveEntryName -Path $Fixture -ResourceId 131 -NestedEntryName 'ProjectWithContent-1.0.0.0-beta-full.nupkg'

    $Info.Family | Should -Be 'Squirrel'
    $Info.DetectionRoute | Should -Be 'SquirrelPeResource'
    $Info.LauncherGeneration | Should -Be 'Squirrel.Windows'
    $Info.ProductCode | Should -Be 'ProjectWithContent'
    $Info.DisplayVersion | Should -Be '1.0.0.0-beta'
    $Info.RequiredFrameworks | Should -Be @('net45')
    $Info.ResourceMetadata.FrameworkResourceValue | Should -Be 'net45'
    $Info.NupkgPath | Should -Be 'ProjectWithContent-1.0.0.0-beta-full.nupkg'
    $OuterEntries | Should -Contain 'Update.exe'
    $OuterEntries | Should -Contain 'ProjectWithContent-1.0.0.0-beta-full.nupkg'
    $PackageEntries | Should -Contain 'lib/net40/project-with-content.exe'
  }

  It 'Should parse the controlled application-complete Clowd.Squirrel 2.7.98 DATA 205 fixture' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Squirrel\Clowd.Squirrel\2.7.98-pre\Clowd-3.4.287-Setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The controlled Clowd.Squirrel 2.7.98-pre fixture is not cached.'
      return
    }

    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be '39DFBB7880B5C4B928A4B54AC9E350ECE6AF990E27D23866AC1B912127CFF30A'
    $Info = Get-SquirrelInfo -Path $Fixture
    $PackageEntries = Get-SquirrelFixtureArchiveEntryName -Path $Fixture -ResourceId 205

    $Info.Family | Should -Be 'Velopack'
    $Info.DetectionRoute | Should -Be 'ClowdSquirrelPeResource'
    $Info.LauncherGeneration | Should -Be 'Clowd.Squirrel.Resource'
    $Info.ProductCode | Should -Be 'Clowd'
    $Info.DisplayVersion | Should -Be '3.4.287'
    $Info.Publisher | Should -Be 'Caelan Sayler'
    $Info.Architecture | Should -Be 'x64'
    $Info.RuntimeDependencies | Should -Be @('net6.0.2-x64')
    $Info.RequiredFrameworks | Should -Be @('net6.0.2-x64')
    $Info.ResourceMetadata.AppId | Should -Be 'Clowd'
    $Info.ResourceMetadata.BundledPackageName | Should -Be 'Clowd-3.4.287-full.nupkg'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Log'
    $PackageEntries | Should -Contain 'lib/native/Clowd.exe'
    $PackageEntries | Should -Contain 'lib/native/Squirrel.exe'
  }

  It 'Should parse the upstream Squirrel.Windows 2.0.1 migration fixture' {
    $Fixture = Get-InstallerFixture -Name 'LegacyTestApp-SquirrelWinV2-Setup.exe' -Url 'https://raw.githubusercontent.com/velopack/velopack/d8a969816a98de41c6fdff6270e280aae435226e/test/fixtures/LegacyTestApp-SquirrelWinV2-Setup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.Family | Should -Be 'Squirrel'
    $Info.DetectionRoute | Should -Be 'SquirrelPeResource'
    $Info.LauncherGeneration | Should -Be 'Squirrel.Windows'
    $Info.ProductCode | Should -Be 'LegacyTestApp'
    $Info.DisplayVersion | Should -Be '1.0.0'
    $Info.NupkgPath | Should -Be 'LegacyTestApp-1.0.0-full.nupkg'
  }

  It 'Should parse the upstream Clowd.Squirrel 2.11.1 migration fixture without modern switches' {
    $Fixture = Get-InstallerFixture -Name 'LegacyTestApp-ClowdV2-Setup.exe' -Url 'https://raw.githubusercontent.com/velopack/velopack/d8a969816a98de41c6fdff6270e280aae435226e/test/fixtures/LegacyTestApp-ClowdV2-Setup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.Family | Should -Be 'Velopack'
    $Info.DetectionRoute | Should -Be 'VelopackBundle'
    $Info.LauncherGeneration | Should -Be 'Clowd.Squirrel.Bundle'
    $Info.ProductCode | Should -Be 'LegacyTestApp'
    $Info.Architecture | Should -Be 'x86'
    $Info.InstallerSwitches.Silent | Should -Be '--silent'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Log'
  }

  It 'Should parse the upstream late Clowd.Squirrel migration fixture without modern switches' {
    $Fixture = Get-InstallerFixture -Name 'LegacyTestApp-ClowdV3-Setup.exe' -Url 'https://raw.githubusercontent.com/velopack/velopack/d8a969816a98de41c6fdff6270e280aae435226e/test/fixtures/LegacyTestApp-ClowdV3-Setup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.Family | Should -Be 'Velopack'
    $Info.DetectionRoute | Should -Be 'VelopackBundle'
    $Info.LauncherGeneration | Should -Be 'Clowd.Squirrel.Bundle'
    $Info.ProductCode | Should -Be 'LegacyTestApp'
    $Info.Architecture | Should -Be 'x86'
    $Info.InstallerSwitches.Silent | Should -Be '--silent'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Log'
  }

  It 'Should parse the upstream Velopack 0.0.84 migration fixture with Rust setup policy' {
    $Fixture = Get-InstallerFixture -Name 'LegacyTestApp-Velopack0084-Setup.exe' -Url 'https://raw.githubusercontent.com/velopack/velopack/1cae116d7850e6598fd8e486a8f1c27bab465954/test/fixtures/LegacyTestApp-Velopack0084-Setup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.Family | Should -Be 'Velopack'
    $Info.DetectionRoute | Should -Be 'VelopackBundle'
    $Info.LauncherGeneration | Should -Be 'Velopack'
    $Info.ProductCode | Should -Be 'LegacyTestApp'
    $Info.MainExecutable | Should -Be 'LegacyTestApp.exe'
    $Info.InstallerSwitches.InstallLocation | Should -Be '--installto "<INSTALLPATH>"'
    $Info.InstallerSwitches.Log | Should -Be '--log "<LOGPATH>"'
  }

  It 'Should parse the upstream Velopack 1.2.98 migration fixture and corroborate its payload architecture' {
    $Fixture = Get-InstallerFixture -Name 'LegacyTestApp-Velopack1298-Setup.exe' -Url 'https://raw.githubusercontent.com/velopack/velopack/413446c01ce314f2faab0bac974447f36b3092ce/test/fixtures/LegacyTestApp-Velopack1298-Setup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.Family | Should -Be 'Velopack'
    $Info.DetectionRoute | Should -Be 'VelopackBundle'
    $Info.LauncherGeneration | Should -Be 'Velopack'
    $Info.ProductCode | Should -Be 'LegacyTestApp'
    $Info.MainExecutable | Should -Be 'TestApp.exe'
    $Info.PackageRid | Should -Be 'win'
    $Info.Architecture | Should -Be 'x64'
    $Info.PayloadArchitectures | Should -Be @('x64')
    $Info.PayloadArchitectureInfo.RelativePath | Should -Be 'lib/app/TestApp.exe'
    $Info.InstallerSwitches.InstallLocation | Should -Be '--installto "<INSTALLPATH>"'
    $Info.InstallerSwitches.Log | Should -Be '--log "<LOGPATH>"'
  }
}
