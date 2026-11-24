. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldInstallScriptTestSetup.ps1')

Describe 'InstallScript media structures' -Tag Unit {
  It 'rejects malformed and oversized script headers without probing arbitrary strings' {
    $Path = Join-Path $TestDrive 'invalid.inx'
    [IO.File]::WriteAllBytes($Path, [byte[]]::new(128))
    { Invoke-InstallShieldInstallScriptAnalysis -Path $Path } | Should -Throw '*supported decoded or scrambled InstallScript header*'
  }

  It 'rejects proprietary cabinet strings that escape the declared file table' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerEvidence.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Cabinet.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $Path = Join-Path $TestDrive 'malformed-data1.hdr'
    $Bytes = [byte[]]::new(72)
    foreach ($Field in @(
        @{ Offset = 0; Value = [uint32]0x28635349 } # ISc(
        @{ Offset = 4; Value = [uint32]0x04000A8C } # Modern version family
        @{ Offset = 12; Value = [uint32]20 }        # Descriptor offset
        @{ Offset = 16; Value = [uint32]48 }        # Descriptor size
        @{ Offset = 32; Value = [uint32]48 }        # File-table offset
        @{ Offset = 40; Value = [uint32]4 }         # File-table size
        @{ Offset = 44; Value = [uint32]4 }         # Mirrored file-table size
        @{ Offset = 48; Value = [uint32]1 }         # Directory count
        @{ Offset = 68; Value = [uint32]8 }         # Escapes four-byte table
      )) {
      [BitConverter]::GetBytes($Field.Value).CopyTo($Bytes, $Field.Offset)
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)

    { [Dumplings.InstallShield.InstallShieldCabinetExtractor]::List($Path) } |
      Should -Throw '*directory name offset is outside*'
  }

  It 'rejects a proprietary cabinet catalog whose object count exceeds parser limits' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $Path = Join-Path $TestDrive 'oversized-catalog-data1.hdr'
    $Bytes = [byte[]]::new(72)
    foreach ($Field in @(
        @{ Offset = 0; Value = [uint32]0x28635349 }
        @{ Offset = 4; Value = [uint32]0x04000A8C }
        @{ Offset = 12; Value = [uint32]20 }
        @{ Offset = 16; Value = [uint32]48 }
        @{ Offset = 32; Value = [uint32]48 }
        @{ Offset = 40; Value = [uint32]4 }
        @{ Offset = 44; Value = [uint32]4 }
        @{ Offset = 48; Value = [uint32]1 }
        @{ Offset = 60; Value = [uint32]100001 }
      )) {
      [BitConverter]::GetBytes($Field.Value).CopyTo($Bytes, $Field.Offset)
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)

    { [Dumplings.InstallShield.InstallShieldCabinetExtractor]::List($Path) } |
      Should -Throw '*catalog counts exceed parser limits*'
  }

  It 'parses source-backed InstallScript media registry sets and shell objects' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
    . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
    $Path = Join-Path $TestDrive 'media-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path)

    $Inspection.Entries | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.Warnings | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.RegistrySets | Should -HaveCount 1
    $Inspection.MediaMetadata.RegistrySets[0].Name | Should -Be '<Default>'
    $Inspection.MediaMetadata.FileGroups.Name | Should -Contain 'Main Component'
    $Inspection.MediaMetadata.Components.Name | Should -Contain '<Data>\Main'
    $Inspection.MediaMetadata.SetupTypes | Should -HaveCount 1
    $Inspection.MediaMetadata.SetupTypes[0].Features | Should -Contain '<Data>\Main'
    $Inspection.MediaMetadata.RegistryWrites | Should -HaveCount 1
    $Inspection.MediaMetadata.RegistryWrites[0].Root | Should -Be 'HKLM'
    $Inspection.MediaMetadata.RegistryWrites[0].Key | Should -Be 'Software\Dumplings\Media'
    $Inspection.MediaMetadata.RegistryWrites[0].Data | Should -Be 'Dumplings Media App'
    $Inspection.MediaMetadata.RegistryWrites[0].Features | Should -Contain '<Data>\Main'
    $Inspection.MediaMetadata.RegistryWrites[0].SetupTypes | Should -Contain 'Complete'
    $Inspection.MediaMetadata.Shortcuts | Should -HaveCount 1
    $Inspection.MediaMetadata.Shortcuts[0].Name | Should -Be 'Dumplings Visible Shortcut'
    $Inspection.MediaMetadata.Shortcuts[0].Target | Should -Be '<TARGETDIR>\Dumplings.exe'
    $Inspection.MediaMetadata.Shortcuts[0].Arguments | Should -Be '--silent'
    $Inspection.MediaMetadata.Shortcuts[0].Component | Should -Be 'Main Component'
    $Inspection.MediaMetadata.Shortcuts[0].HotKey | Should -Be 4660
    $Inspection.MediaMetadata.Shortcuts[0].ShowCommand | Should -Be 3
    $Inspection.MediaMetadata.Shortcuts[0].Features | Should -Contain '<Data>\Main'
  }

  It 'parses packed multi-language setup types and flagged registry-key counts' {
    $Path = Join-Path $TestDrive 'media-multilanguage-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $DescriptorBase = 0x20
    $WriteUInt16 = { param([int]$Offset, [uint16]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt32 = { param([int]$Offset, [uint32]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }

    # Multi-language media stores a contiguous LCID array followed by one
    # shared setup-type count and table pointer.
    & $WriteUInt16 ($DescriptorBase + 0x30) ([uint16]2)
    & $WriteUInt32 ($DescriptorBase + 0xAD8) ([uint32]1033)
    & $WriteUInt32 ($DescriptorBase + 0xADC) ([uint32]1041)
    & $WriteUInt32 ($DescriptorBase + 0xAE0) ([uint32]1)
    & $WriteUInt32 ($DescriptorBase + 0xAE4) ([uint32]0xAEC)
    & $WriteUInt32 ($DescriptorBase + 0xAEC) ([uint32]0xAF0)
    & $WriteUInt32 ($DescriptorBase + 0xAF0) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAF4) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAF8) ([uint32]0xB70)
    & $WriteUInt32 ($DescriptorBase + 0xAFC) ([uint32]1)
    & $WriteUInt32 ($DescriptorBase + 0xB00) ([uint32]0xB04)

    # InstallShield uses the high bit as key-control metadata. It is not part
    # of the 15-bit registry-value count stored in the same field.
    & $WriteUInt16 ($DescriptorBase + 0x370 + 8) ([uint16]0x8001)
    [IO.File]::WriteAllBytes($Path, $Bytes)

    $Metadata = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path).MediaMetadata

    $Metadata.Warnings | Should -BeNullOrEmpty
    $Metadata.SetupTypes | Should -HaveCount 2
    $Metadata.SetupTypes.Language | Should -Contain 1033
    $Metadata.SetupTypes.Language | Should -Contain 1041
    $Metadata.SetupTypes.Name | Should -Not -Contain ''
    $Metadata.RegistryWrites | Should -HaveCount 1
    $Metadata.RegistryWrites[0].Data | Should -Be 'Dumplings Media App'
  }

  It 'decodes source-backed InstallScript media registry value encodings' {
    $Path = Join-Path $TestDrive 'media-registry-types-data1.hdr'
    New-TestInstallShieldRegistryTypeHeader -Path $Path

    $Writes = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path).MediaMetadata.RegistryWrites

    ($Writes | Where-Object Name -EQ 'String').Data | Should -Be 'Text'
    ($Writes | Where-Object Name -EQ 'Expand').Data | Should -Be '%PATH%'
    [byte[]](($Writes | Where-Object Name -EQ 'Binary').Data) | Should -Be ([byte[]](1, 2, 165, 255))
    ($Writes | Where-Object Name -EQ 'Dword').Data | Should -Be ([uint32]123456789)
    [string[]](($Writes | Where-Object Name -EQ 'Multi').Data) | Should -Be @('First', 'Second')
    $Writes.Complete | Should -Not -Contain $false
  }

  It 'keeps an ordinary catalog readable when media extension pointers are malformed' {
    $Path = Join-Path $TestDrive 'malformed-media-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path -MalformedRegistryPointer

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path)

    $Inspection.Entries | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.RegistryWrites | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.Shortcuts | Should -HaveCount 1
    $Inspection.MediaMetadata.Warnings -join ' ' | Should -Match 'registry records are malformed or unsupported'
  }

  It 'rolls back an ungrounded Unicode optional graph without hiding an independent valid graph' {
    $Path = Join-Path $TestDrive 'transactional-major22-data1.hdr'
    New-TestInstallShieldMediaHeader -Path $Path -RawVersion 0x04000898 -MalformedRegistryPointer

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Path)

    $Inspection.MediaMetadata.MajorVersion | Should -Be 22
    $Inspection.MediaMetadata.RegistrySets | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.RegistryWrites | Should -BeNullOrEmpty
    $Inspection.MediaMetadata.Shortcuts | Should -HaveCount 1
    $Inspection.MediaMetadata.Warnings -join ' ' | Should -Not -Match 'registry records are malformed or unsupported'
  }

  It 'promotes only default or statically selected InstallScript media records' {
    $DefaultWrite = [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Default'; Name = 'Value'; Type = 'REG_SZ'; Data = 'Default'; RegistrySet = '<Default>'; IsDefaultSet = $true; Components = @(); Complete = $true }
    $NamedWrite = [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Named'; Name = 'Value'; Type = 'REG_SZ'; Data = 'Named'; RegistrySet = 'Optional Set'; IsDefaultSet = $false; Components = @(); Complete = $true }
    $ComponentWrite = [pscustomobject]@{ Root = 'HKCR'; Key = '.dumplings'; Name = ''; Type = 'REG_SZ'; Data = 'Dumplings.File'; RegistrySet = 'Component Set'; IsDefaultSet = $false; Components = @('Main Component'); Complete = $true }
    $Shortcut = [pscustomobject]@{ Name = 'Dumplings'; Target = '<TARGETDIR>\Dumplings.exe'; Component = ''; Confidence = 'ConditionalMediaRecord' }
    $Installer = [pscustomobject]@{
      InstallShieldCabinetSupport = [pscustomobject]@{
        RegistrySets   = @()
        RegistryWrites = @($DefaultWrite, $NamedWrite, $ComponentWrite)
        ShellFolders   = @()
        Shortcuts      = @($Shortcut)
      }
    }
    $Analysis = [pscustomobject]@{
      StaticCalls               = @()
      RegistryWrites            = @()
      Shortcuts                 = @()
      Diagnostics               = @()
      Protocols                 = @()
      FileExtensions            = @()
      ProtocolAssociations      = @()
      FileExtensionAssociations = @()
      RegistryAssociationInfo   = $null
    }
    $Module = Get-Module InstallShieldInstallScript

    $Conditional = & $Module { param($Installer, $Analysis) Merge-InstallShieldInstallScriptMediaEvidence -Installer $Installer -Analysis $Analysis } $Installer $Analysis

    $Conditional.RegistryWrites.Key | Should -Be 'Software\Default'
    $Conditional.ConditionalMediaRegistryWrites.Key | Should -Be @('Software\Named', '.dumplings')
    ($Conditional.ConditionalMediaRegistryWrites | Where-Object Key -EQ '.dumplings').Confidence | Should -Be 'ComponentTransfer'
    $Conditional.Shortcuts | Should -BeNullOrEmpty

    $Analysis.StaticCalls = @(
      [pscustomobject]@{ Target = 'CreateRegistrySet'; Arguments = @('Optional Set'); Complete = $true }
      [pscustomobject]@{ Target = '_CreateShellObjects'; Arguments = @(''); Complete = $true }
    )
    $Selected = & $Module { param($Installer, $Analysis) Merge-InstallShieldInstallScriptMediaEvidence -Installer $Installer -Analysis $Analysis } $Installer $Analysis

    $Selected.RegistryWrites.Key | Should -Contain 'Software\Named'
    $Selected.ConditionalMediaRegistryWrites.Key | Should -Be '.dumplings'
    $Selected.ConditionalFileExtensions | Should -Contain 'dumplings'
    $Selected.Shortcuts.Name | Should -Contain 'Dumplings'
    $Selected.Shortcuts[0].Confidence | Should -Be 'ReachedMediaShellObjects'
  }

  It 'validates registry and shell layouts built by official InstallShield 2026 R1 when cached' {
    $RegistryPath = Join-Path $Script:InstallShieldFixtureDirectory '2026R1\Differential\RegistryHKLM4\data1.hdr'
    $ShellPath = Join-Path $Script:InstallShieldFixtureDirectory '2026R1\Differential\ShellOnly4\data1.hdr'
    if (-not (Test-Path -LiteralPath $RegistryPath)) { Set-ItResult -Skipped -Because 'the InstallShield 2026 R1 differential media is not cached'; return }

    $Registry = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($RegistryPath).MediaMetadata
    $Shell = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($ShellPath).MediaMetadata

    $Registry.MajorVersion | Should -Be 32
    $Registry.RegistryWrites | Where-Object { $_.Root -eq 'HKLM' -and $_.Key -eq 'SOFTWARE\DumplingsLab\DefaultSet' } | Should -HaveCount 1
    $Registry.RegistryWrites[0].Data | Should -Be 'DumplingsData'
    $Shell.Shortcuts | Should -HaveCount 1
    $Shell.Shortcuts[0].Target | Should -Be '<TARGETDIR>\Sampler.exe'
    $Shell.Shortcuts[0].Arguments | Should -Be '--dumplings'
    $Shell.Shortcuts[0].ShowCommand | Should -Be 1
    $Shell.Shortcuts[0].Features | Should -Contain '<Data>\Main App'
    $Shell.Shortcuts[0].SetupTypes | Should -Contain 'Complete'
    $Registry.Warnings + $Shell.Warnings | Should -BeNullOrEmpty
  }

  It 'validates registry encodings and shortcut fields from official InstallShield 2026 R1 differential media when cached' {
    $Root = Join-Path $Script:InstallShieldFixtureDirectory '2026R1\Differential'
    if (-not (Test-Path -LiteralPath (Join-Path $Root 'RegistryTypes6\data1.hdr'))) { Set-ItResult -Skipped -Because 'the InstallShield 2026 R1 differential media is not cached'; return }
    $Registry = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect((Join-Path $Root 'RegistryTypes6\data1.hdr')).MediaMetadata
    $Shell = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect((Join-Path $Root 'ShellFields7\data1.hdr')).MediaMetadata

    [byte[]](($Registry.RegistryWrites | Where-Object Name -EQ 'BinaryValue').Data) | Should -Be ([byte[]](1, 2, 165, 255))
    ($Registry.RegistryWrites | Where-Object Name -EQ 'DwordValue').Data | Should -Be ([uint32]123456789)
    [string[]](($Registry.RegistryWrites | Where-Object Name -EQ 'MultiValue').Data) | Should -Be @('First', 'Second')
    $Shell.Shortcuts[0].HotKey | Should -Be 4660
    $Shell.Shortcuts[0].ShowCommand | Should -Be 3
    $Shell.Shortcuts[0].Features | Should -Contain '<Data>\Main App'
    $Shell.Shortcuts[0].SetupTypes | Should -Contain 'Complete'
    $Registry.Warnings + $Shell.Warnings | Should -BeNullOrEmpty
  }
}
