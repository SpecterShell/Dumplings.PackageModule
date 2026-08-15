. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

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

  function New-TestBurnBundle {
    param(
      [Parameter(Mandatory)][string]$Root,
      [Parameter(Mandatory)][string]$Name,
      [ValidateSet('Normal', 'Traversal', 'Reserved', 'Ambiguous', 'DuplicateIndex', 'SizeMismatch')][string]$ManifestMode = 'Normal',
      [switch]$Signed
    )

    $FixtureRoot = Join-Path $Root ([IO.Path]::GetFileNameWithoutExtension($Name))
    $null = New-Item -Path $FixtureRoot -ItemType Directory -Force
    $DefaultSource = Join-Path $FixtureRoot 'DefaultSource'
    $CustomSource = Join-Path $FixtureRoot 'CustomSource'
    $UXSource = Join-Path $FixtureRoot 'UXSource'
    $null = New-Item -Path $DefaultSource, $CustomSource, $UXSource -ItemType Directory -Force

    [IO.File]::WriteAllText((Join-Path $DefaultSource 'a0'), 'default payload')
    [IO.File]::WriteAllText((Join-Path $DefaultSource 'a1'), 'duplicate payload')
    [IO.File]::WriteAllText((Join-Path $DefaultSource 'orphan.bin'), 'unmapped attached payload')
    [IO.File]::WriteAllText((Join-Path $CustomSource 'b0'), 'custom payload')
    $DefaultCabinetPath = Join-Path $FixtureRoot 'default.cab'
    $CustomCabinetPath = Join-Path $FixtureRoot 'custom.cab'
    [Microsoft.Deployment.Compression.Cab.CabInfo]::new($DefaultCabinetPath).Pack($DefaultSource)
    [Microsoft.Deployment.Compression.Cab.CabInfo]::new($CustomCabinetPath).Pack($CustomSource)

    $DefaultCabinetSize = (Get-Item -LiteralPath $DefaultCabinetPath).Length
    $CustomCabinetSize = (Get-Item -LiteralPath $CustomCabinetPath).Length
    $UXFilePath = switch ($ManifestMode) {
      'Traversal' { '..\escape.xml' }
      'Reserved' { 'CON\theme.xml' }
      default { 'assets\theme.xml' }
    }
    $DefaultAttachedIndex = $ManifestMode -eq 'Ambiguous' ? '' : ' AttachedIndex="1"'
    $CustomAttachedIndex = switch ($ManifestMode) {
      'Ambiguous' { '' }
      'DuplicateIndex' { ' AttachedIndex="1"' }
      default { ' AttachedIndex="2"' }
    }
    $CustomManifestSize = $ManifestMode -eq 'SizeMismatch' ? ($CustomCabinetSize + 1) : $CustomCabinetSize
    $ManifestText = @"
<BurnManifest xmlns="http://wixtoolset.org/schemas/v4/2008/Burn">
  <UX>
    <Payload Id="ux" FilePath="$UXFilePath" FileSize="10" SourcePath="u0" />
  </UX>
  <Container Id="WixAttachedContainer" FileSize="$DefaultCabinetSize" Attached="yes"$DefaultAttachedIndex />
  <Container Id="CustomContainer" FileSize="$CustomManifestSize" Attached="yes"$CustomAttachedIndex />
  <Container Id="DetachedContainer" FileSize="100" Attached="no" />
  <Payload Id="default" FilePath="packages\shared.msi" FileSize="15" Packaging="embedded" SourcePath="a0" Container="WixAttachedContainer" />
  <Payload Id="duplicate" FilePath="packages\shared.msi" FileSize="17" Packaging="embedded" SourcePath="a1" Container="WixAttachedContainer" />
  <Payload Id="custom" FilePath="nested\tool.exe" FileSize="14" Packaging="embedded" SourcePath="b0" Container="CustomContainer" />
  <Payload Id="external" FilePath="remote.exe" FileSize="1" Packaging="external" SourcePath="remote.exe" />
  <Payload Id="detached" FilePath="detached.exe" FileSize="1" Packaging="embedded" SourcePath="d0" Container="DetachedContainer" />
</BurnManifest>
"@
    [IO.File]::WriteAllText((Join-Path $UXSource '0'), $ManifestText, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $UXSource 'u0'), 'ux payload')
    [IO.File]::WriteAllText((Join-Path $UXSource 'unlisted.dat'), 'unmapped UX payload')
    $UXCabinetPath = Join-Path $FixtureRoot 'ux.cab'
    [Microsoft.Deployment.Compression.Cab.CabInfo]::new($UXCabinetPath).Pack($UXSource)

    $UXBytes = [IO.File]::ReadAllBytes($UXCabinetPath)
    $DefaultBytes = [IO.File]::ReadAllBytes($DefaultCabinetPath)
    $CustomBytes = [IO.File]::ReadAllBytes($CustomCabinetPath)
    $StubSize = 0x400
    $UXEnd = $StubSize + $UXBytes.Length
    $OriginalSignatureOffset = $Signed ? (($UXEnd + 7) -band -8) : 0
    $OriginalSignatureSize = $Signed ? 32 : 0
    $EngineSize = $Signed ? ($OriginalSignatureOffset + $OriginalSignatureSize) : $UXEnd
    $AttachedEnd = $EngineSize + $DefaultBytes.Length + $CustomBytes.Length
    $CurrentSignatureOffset = $Signed ? (($AttachedEnd + 7) -band -8) : 0
    $CurrentSignatureSize = $Signed ? 24 : 0

    $Stub = [byte[]]::new($StubSize)
    function Write-TestUInt16([int]$Offset, [uint16]$Value) { [BitConverter]::GetBytes($Value).CopyTo($Stub, $Offset) }
    function Write-TestUInt32([int]$Offset, [uint32]$Value) { [BitConverter]::GetBytes($Value).CopyTo($Stub, $Offset) }
    $PEOffset = 0x80
    $OptionalHeaderOffset = $PEOffset + 24
    $OptionalHeaderSize = 0xE0
    $DataDirectoryOffset = $OptionalHeaderOffset + 96
    $SectionOffset = $OptionalHeaderOffset + $OptionalHeaderSize
    Write-TestUInt16 0 0x5A4D
    Write-TestUInt32 0x3C $PEOffset
    Write-TestUInt32 $PEOffset 0x00004550
    Write-TestUInt16 ($PEOffset + 4) 0x014C
    Write-TestUInt16 ($PEOffset + 6) 1
    Write-TestUInt16 ($PEOffset + 20) $OptionalHeaderSize
    Write-TestUInt16 ($PEOffset + 22) 0x0102
    Write-TestUInt16 $OptionalHeaderOffset 0x010B
    Write-TestUInt32 ($OptionalHeaderOffset + 28) 0x00400000
    Write-TestUInt32 ($OptionalHeaderOffset + 32) 0x1000
    Write-TestUInt32 ($OptionalHeaderOffset + 36) 0x200
    Write-TestUInt32 ($OptionalHeaderOffset + 56) 0x2000
    Write-TestUInt32 ($OptionalHeaderOffset + 60) $StubSize
    Write-TestUInt16 ($OptionalHeaderOffset + 68) 2
    Write-TestUInt32 ($OptionalHeaderOffset + 92) 16
    if ($Signed) {
      Write-TestUInt32 ($DataDirectoryOffset + 32) $CurrentSignatureOffset
      Write-TestUInt32 ($DataDirectoryOffset + 36) $CurrentSignatureSize
    }
    [Text.Encoding]::ASCII.GetBytes('.wixburn').CopyTo($Stub, $SectionOffset)
    Write-TestUInt32 ($SectionOffset + 8) 0x200
    Write-TestUInt32 ($SectionOffset + 12) 0x1000
    Write-TestUInt32 ($SectionOffset + 16) 0x200
    Write-TestUInt32 ($SectionOffset + 20) 0x200

    $BurnOffset = 0x200
    Write-TestUInt32 ($BurnOffset + 0x00) 0x00F14300
    Write-TestUInt32 ($BurnOffset + 0x04) 2
    [Guid]::NewGuid().ToByteArray().CopyTo($Stub, $BurnOffset + 0x08)
    Write-TestUInt32 ($BurnOffset + 0x18) $StubSize
    Write-TestUInt32 ($BurnOffset + 0x20) $OriginalSignatureOffset
    Write-TestUInt32 ($BurnOffset + 0x24) $OriginalSignatureSize
    Write-TestUInt32 ($BurnOffset + 0x28) 1
    Write-TestUInt32 ($BurnOffset + 0x2C) 3
    Write-TestUInt32 ($BurnOffset + 0x30) $UXBytes.Length
    Write-TestUInt32 ($BurnOffset + 0x34) $DefaultBytes.Length
    Write-TestUInt32 ($BurnOffset + 0x38) $CustomBytes.Length

    $BundlePath = Join-Path $FixtureRoot $Name
    $Output = [IO.File]::Open($BundlePath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $Output.Write($Stub)
      $Output.Write($UXBytes)
      if ($Signed) {
        $Output.Write([byte[]]::new($OriginalSignatureOffset - $Output.Position))
        $Output.Write([byte[]]::new($OriginalSignatureSize))
      }
      $Output.Write($DefaultBytes)
      $Output.Write($CustomBytes)
      if ($Signed) {
        $Output.Write([byte[]]::new($CurrentSignatureOffset - $Output.Position))
        $Output.Write([byte[]]::new($CurrentSignatureSize))
      }
    } finally {
      $Output.Dispose()
    }

    return [pscustomobject]@{
      Path                   = $BundlePath
      UXSize                 = $UXBytes.Length
      EngineSize             = $EngineSize
      CurrentSignatureOffset = $CurrentSignatureOffset
      CurrentSignatureSize   = $CurrentSignatureSize
    }
  }
}

Describe 'Burn engine ranges and extraction' {
  It 'Uses the original and current signature ranges for a signed bundle' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'signed.exe' -Signed
    $Stream = [IO.File]::OpenRead($Fixture.Path)
    $StubPath = $null
    try {
      $Stream.Position = 37
      $Info = Get-BurnEngineInfo -Stream $Stream
      $Stream.Position | Should -Be 37
      $Info.UXAddress | Should -Be 0x400
      $Info.UXSize | Should -Be $Fixture.UXSize
      $Info.EngineSize | Should -Be $Fixture.EngineSize
      $Info.CurrentSignatureOffset | Should -Be $Fixture.CurrentSignatureOffset
      $Info.CurrentSignatureSize | Should -Be $Fixture.CurrentSignatureSize
      $Info.AttachedContainers.Kind | Should -Be @('UX', 'Attached', 'Attached')
      $Info.AttachedContainers.Offset[1] | Should -Be $Fixture.EngineSize

      $Stream.Position = 51
      $StubPath = Get-BurnStub -Stream $Stream
      $Stream.Position | Should -Be 51
      (Get-Item -LiteralPath $StubPath).Length | Should -Be $Fixture.UXSize
      (Get-BurnManifest -StubPath $StubPath).DocumentElement.LocalName | Should -Be 'BurnManifest'
    } finally {
      $Stream.Dispose()
      if ($StubPath) { Remove-Item -LiteralPath $StubPath -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Uses the UX end as the engine boundary for an unsigned bundle' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'unsigned.exe'
    $Info = Get-BurnEngineInfo -Path $Fixture.Path

    $Info.OriginalSignatureOffset | Should -Be 0
    $Info.CurrentSignatureOffset | Should -Be 0
    $Info.EngineSize | Should -Be (0x400 + $Fixture.UXSize)
    $Info.AttachedContainers[1].Offset | Should -Be $Info.EngineSize
  }

  It 'Uses the current PE signature boundary for a UX-only signed bundle' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'current-signature.exe' -Signed
    $Stream = [IO.File]::Open($Fixture.Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $Stream.Position = 0x220
      $Stream.Write([byte[]]::new(8))
      $Stream.Position = 0x22C
      $Stream.Write([BitConverter]::GetBytes([uint32]1))
    } finally {
      $Stream.Dispose()
    }

    $Info = Get-BurnEngineInfo -Path $Fixture.Path
    $Info.ContainerCount | Should -Be 1
    $Info.EngineSize | Should -Be ($Fixture.CurrentSignatureOffset + $Fixture.CurrentSignatureSize)
    $Info.AttachedContainers | Should -HaveCount 1
  }

  It 'Projects UX, authored containers, unmapped records, and duplicate paths' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'layout.exe' -Signed
    $Destination = Join-Path $TestDrive 'layout-output'
    $Files = @(Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $Destination -CollisionAction Rename -WarningAction SilentlyContinue)
    $RelativePaths = @($Files.FullName | ForEach-Object { [IO.Path]::GetRelativePath($Destination, $_) })

    $RelativePaths | Should -Be @(
      'UX\manifest.xml'
      'UX\assets\theme.xml'
      'UX\unlisted.dat'
      'WixAttachedContainer\packages\shared.msi'
      'WixAttachedContainer\packages\shared (1).msi'
      'WixAttachedContainer\orphan.bin'
      'CustomContainer\nested\tool.exe'
    )
    Get-Content -LiteralPath (Join-Path $Destination 'WixAttachedContainer\packages\shared.msi') -Raw | Should -Be 'default payload'
    Get-Content -LiteralPath (Join-Path $Destination 'WixAttachedContainer\packages\shared (1).msi') -Raw | Should -Be 'duplicate payload'
    Get-Content -LiteralPath (Join-Path $Destination 'CustomContainer\nested\tool.exe') -Raw | Should -Be 'custom payload'
  }

  It 'Matches source CAB paths and leaf names' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'selection.exe'
    $SourceDestination = Join-Path $TestDrive 'source-selection'
    $LeafDestination = Join-Path $TestDrive 'leaf-selection'

    $SourceFiles = @(Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $SourceDestination -Name 'b0' -CollisionAction Error -WarningAction SilentlyContinue)
    $LeafFiles = @(Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $LeafDestination -Name 'theme.xml' -CollisionAction Error -WarningAction SilentlyContinue)

    $SourceFiles | Should -HaveCount 1
    [IO.Path]::GetRelativePath($SourceDestination, $SourceFiles[0].FullName) | Should -Be 'CustomContainer\nested\tool.exe'
    $LeafFiles | Should -HaveCount 1
    [IO.Path]::GetRelativePath($LeafDestination, $LeafFiles[0].FullName) | Should -Be 'UX\assets\theme.xml'
  }

  It 'Creates a temporary destination when DestinationPath is omitted' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'temporary-destination.exe'
    $Files = @(Expand-BurnInstaller -Path $Fixture.Path -Name 'a0' -CollisionAction Error -WarningAction SilentlyContinue)
    $OutputRoot = $Files[0].Directory.Parent.Parent.FullName
    try {
      $Files | Should -HaveCount 1
      [IO.Path]::GetRelativePath($OutputRoot, $Files[0].FullName) | Should -Be 'WixAttachedContainer\packages\shared.msi'
    } finally {
      Remove-Item -LiteralPath $OutputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Applies explicit collision policies only after a collision exists' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'collision.exe'
    $Destination = Join-Path $TestDrive 'collision-output'
    $ExistingPath = Join-Path $Destination 'WixAttachedContainer\packages\shared.msi'
    $null = New-Item -Path ([IO.Path]::GetDirectoryName($ExistingPath)) -ItemType Directory -Force
    Set-Content -LiteralPath $ExistingPath -Value 'existing' -NoNewline

    { Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $Destination -Name 'a0' -CollisionAction Error -WarningAction SilentlyContinue } |
      Should -Throw '*already exists*'
    @(Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $Destination -Name 'a0' -CollisionAction Skip -WarningAction SilentlyContinue) |
      Should -HaveCount 0
    Get-Content -LiteralPath $ExistingPath -Raw | Should -Be 'existing'

    $Overwrite = @(Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $Destination -Name 'a0' -CollisionAction Overwrite -WarningAction SilentlyContinue)
    $Overwrite | Should -HaveCount 1
    Get-Content -LiteralPath $ExistingPath -Raw | Should -Be 'default payload'

    $Rename = @(Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $Destination -Name 'a0' -CollisionAction Rename -WarningAction SilentlyContinue)
    $Rename | Should -HaveCount 1
    $Rename[0].Name | Should -Be 'shared (1).msi'
  }

  It 'Prompts only after detecting a collision' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'prompt.exe'
    $Destination = Join-Path $TestDrive 'prompt-output'
    $ExistingPath = Join-Path $Destination 'WixAttachedContainer\packages\shared.msi'
    $null = New-Item -Path ([IO.Path]::GetDirectoryName($ExistingPath)) -ItemType Directory -Force
    Set-Content -LiteralPath $ExistingPath -Value 'existing' -NoNewline
    Mock Read-InstallerCollisionAction -ModuleName Binary { 'Rename' }

    $Files = @(Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $Destination -Name 'a0' -WarningAction SilentlyContinue)

    $Files[0].Name | Should -Be 'shared (1).msi'
    Should -Invoke Read-InstallerCollisionAction -ModuleName Binary -Times 1 -Exactly
  }

  It 'Distinguishes unavailable payload matches from ordinary no-match selectors' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'unavailable.exe'

    { Expand-BurnInstaller -Path $Fixture.Path -DestinationPath (Join-Path $TestDrive 'external') -Name 'remote.exe' -CollisionAction Error } |
      Should -Throw '*matches only external or detached payloads*'
    { Expand-BurnInstaller -Path $Fixture.Path -DestinationPath (Join-Path $TestDrive 'missing') -Name 'missing.exe' -CollisionAction Error } |
      Should -Throw '*No embedded Burn payload matches*'
  }

  It 'Rejects unsafe paths, ambiguous slots, output overruns, and truncated ranges' {
    $Traversal = New-TestBurnBundle -Root $TestDrive -Name 'traversal.exe' -ManifestMode Traversal
    { Expand-BurnInstaller -Path $Traversal.Path -DestinationPath (Join-Path $TestDrive 'traversal-output') -Name 'u0' -CollisionAction Error } |
      Should -Throw '*path traversal*'

    $Reserved = New-TestBurnBundle -Root $TestDrive -Name 'reserved.exe' -ManifestMode Reserved
    { Expand-BurnInstaller -Path $Reserved.Path -DestinationPath (Join-Path $TestDrive 'reserved-output') -Name 'u0' -CollisionAction Error } |
      Should -Throw '*reserved Windows path component*'

    $Ambiguous = New-TestBurnBundle -Root $TestDrive -Name 'ambiguous.exe' -ManifestMode Ambiguous
    { Expand-BurnInstaller -Path $Ambiguous.Path -DestinationPath (Join-Path $TestDrive 'ambiguous-output') -CollisionAction Error } |
      Should -Throw '*unambiguously map*'

    $DuplicateIndex = New-TestBurnBundle -Root $TestDrive -Name 'duplicate-index.exe' -ManifestMode DuplicateIndex
    { Expand-BurnInstaller -Path $DuplicateIndex.Path -DestinationPath (Join-Path $TestDrive 'duplicate-index-output') -CollisionAction Error } |
      Should -Throw '*uses AttachedIndex 1*'

    $SizeMismatch = New-TestBurnBundle -Root $TestDrive -Name 'size-mismatch.exe' -ManifestMode SizeMismatch
    { Expand-BurnInstaller -Path $SizeMismatch.Path -DestinationPath (Join-Path $TestDrive 'size-mismatch-output') -CollisionAction Error } |
      Should -Throw '*does not match the size declared by .wixburn*'

    $Limited = New-TestBurnBundle -Root $TestDrive -Name 'limited.exe'
    { Expand-BurnInstaller -Path $Limited.Path -DestinationPath (Join-Path $TestDrive 'limited-output') -Name 'a0' -MaximumExpandedBytes 14 -CollisionAction Error } |
      Should -Throw '*configured output limit*'

    $Truncated = New-TestBurnBundle -Root $TestDrive -Name 'truncated.exe'
    $File = [IO.File]::Open($Truncated.Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $File.SetLength($File.Length - 1) } finally { $File.Dispose() }
    { Get-BurnEngineInfo -Path $Truncated.Path } | Should -Throw '*installer*'
  }

  It 'Rejects a malformed cabinet before writing selected outputs' {
    $Fixture = New-TestBurnBundle -Root $TestDrive -Name 'malformed-cabinet.exe'
    $EngineInfo = Get-BurnEngineInfo -Path $Fixture.Path
    $Stream = [IO.File]::Open($Fixture.Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $Stream.Position = $EngineInfo.AttachedContainers[1].Offset
      $Stream.WriteByte(0)
    } finally {
      $Stream.Dispose()
    }
    $Destination = Join-Path $TestDrive 'malformed-cabinet-output'

    { Expand-BurnInstaller -Path $Fixture.Path -DestinationPath $Destination -Name 'a0' -CollisionAction Error } | Should -Throw
    @(Get-ChildItem -LiteralPath $Destination -Recurse -File -ErrorAction SilentlyContinue) | Should -HaveCount 0
  }
}

Describe 'Burn extraction real fixtures' {
  It 'Extracts the Grammarly attached MSI under its authored container' {
    $Fixture = Get-InstallerFixture -Name 'GrammarlyAddInSetup6.8.263.exe' -Url 'https://download-office.grammarly.com/installer/GrammarlyAddInSetup6.8.263.exe'
    $Destination = Join-Path $TestDrive 'grammarly'
    $Files = @(Expand-BurnInstaller -Path $Fixture -DestinationPath $Destination -Name 'GrammarlyInstaller_x64.msi' -CollisionAction Error -WarningAction SilentlyContinue)

    $Files | Should -HaveCount 1
    [IO.Path]::GetRelativePath($Destination, $Files[0].FullName) | Should -Be 'WixAttachedContainer\GrammarlyInstaller_x64.msi'
    [IO.File]::ReadAllBytes($Files[0].FullName)[0..7] | Should -Be @(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
  }

  It 'Extracts duplicate Python payload names with deterministic collision suffixes' {
    $Fixture = Get-InstallerFixture -Name 'python-3.14.6-amd64.exe' -Url 'https://www.python.org/ftp/python/3.14.6/python-3.14.6-amd64.exe'
    $Destination = Join-Path $TestDrive 'python'
    $Files = @(Expand-BurnInstaller -Path $Fixture -DestinationPath $Destination -Name 'core.msi' -CollisionAction Rename -WarningAction SilentlyContinue)

    $Files | Should -HaveCount 2
    $Files.Name | Should -Be @('core.msi', 'core (1).msi')
    foreach ($File in $Files) { [IO.File]::ReadAllBytes($File.FullName)[0..7] | Should -Be @(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1) }
  }

  It 'Extracts the complete embedded Enpass projection' {
    $Fixture = Get-InstallerFixture -Name 'Enpass-setup.exe' -Url 'https://dl.enpass.io/stable/windows/setup/x64/6.12.1.2417/Enpass-setup.exe'
    $Destination = Join-Path $TestDrive 'enpass'
    $Files = @(Expand-BurnInstaller -Path $Fixture -DestinationPath $Destination -CollisionAction Error -WarningAction SilentlyContinue)

    $Files.Count | Should -BeGreaterThan 3
    $Files.FullName | Should -Contain (Join-Path $Destination 'UX\manifest.xml')
    $Files.FullName | Should -Contain (Join-Path $Destination 'WixAttachedContainer\Enpass.msi')
  }

  It 'Reads and selectively expands the large Jabra attached container' {
    $Fixture = Get-InstallerFixture -Name 'JabraDirectSetup.exe' -Url 'https://jabraxpressonlineprdstor.blob.core.windows.net/jdo/JabraDirectSetup.exe'
    $Destination = Join-Path $TestDrive 'jabra'
    $Files = @(Expand-BurnInstaller -Path $Fixture -DestinationPath $Destination -Name '*.msi' -CollisionAction Rename -WarningAction SilentlyContinue)

    $Files.Count | Should -BeGreaterThan 0
    foreach ($File in $Files) { [IO.File]::ReadAllBytes($File.FullName)[0..7] | Should -Be @(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1) }
  }
}

Describe 'Burn unsupported architecture parser' {
  It 'Should detect the x64-only Enpass Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'Enpass-setup.exe' -Url 'https://dl.enpass.io/stable/windows/setup/x64/6.12.1.2417/Enpass-setup.exe'
    $Info = Get-BurnPackageArchitectureInfo -Path $Fixture

    $Info.BundleArchitecture | Should -Be 'x86'
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Read-UnsupportedArchitecturesFromBurn -Path $Fixture | Should -Be @('x86')
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeFalse
  }

  It 'Should detect the x64-only Jabra Direct Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'JabraDirectSetup.exe' -Url 'https://jabraxpressonlineprdstor.blob.core.windows.net/jdo/JabraDirectSetup.exe'
    $Info = Get-BurnPackageArchitectureInfo -Path $Fixture

    $Info.BundleArchitecture | Should -Be 'x86'
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Read-UnsupportedArchitecturesFromBurn -Path $Fixture | Should -Be @('x86')
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-BurnUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeFalse
  }
}

Describe 'Burn scope parser' {
  It 'Should detect a default-machine Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'Enpass-setup.exe' -Url 'https://dl.enpass.io/stable/windows/setup/x64/6.12.1.2417/Enpass-setup.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.SupportsDualScope | Should -BeFalse
    Read-ScopeFromBurn -Path $Fixture | Should -Be 'machine'
    Read-SupportedScopesFromBurn -Path $Fixture | Should -Be @('machine')
    Test-BurnDualScope -Path $Fixture | Should -BeFalse
  }

  It 'Should detect a default-user Burn installer' {
    $Fixture = Get-InstallerFixture -Name 'Proton Drive Setup 3.0.2.exe' -Url 'https://proton.me/download/drive/windows/3.0.2/x64/Proton%20Drive%20Setup%203.0.2.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    Read-ScopeFromBurn -Path $Fixture | Should -Be 'user'
    Read-SupportedScopesFromBurn -Path $Fixture | Should -Be @('user')
    Test-BurnDualScope -Path $Fixture | Should -BeFalse
  }

  It 'Should not treat hidden all-users Grammarly packages as command-line dual-scope' {
    $Fixture = Get-InstallerFixture -Name 'GrammarlyAddInSetup6.8.263.exe' -Url 'https://download-office.grammarly.com/installer/GrammarlyAddInSetup6.8.263.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.PackageScopes | Should -Contain 'machine'
    $Info.PackageScopes | Should -Contain 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    Test-BurnDualScope -Path $Fixture | Should -BeFalse
  }

  It 'Should detect Python 3.13 as dual-scope through InstallAllUsers' {
    $Fixture = Get-InstallerFixture -Name 'python-3.13.9-amd64.exe' -Url 'https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.OverridableScopeVariables | Should -Contain 'InstallAllUsers'
    Test-BurnDualScope -Path $Fixture | Should -BeTrue
  }

  It 'Should detect Python 3.14 as dual-scope through InstallAllUsers' {
    $Fixture = Get-InstallerFixture -Name 'python-3.14.6-amd64.exe' -Url 'https://www.python.org/ftp/python/3.14.6/python-3.14.6-amd64.exe'
    $Info = Get-BurnScopeInfo -Path $Fixture

    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.OverridableScopeVariables | Should -Contain 'InstallAllUsers'
    Read-SupportedScopesFromBurn -Path $Fixture | Should -Be @('user', 'machine')
    Test-BurnDualScope -Path $Fixture | Should -BeTrue
  }
}
