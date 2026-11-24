. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive

  function New-TestCreateInstallFixture {
    param(
      [Parameter(Mandatory)][string]$Path,
      [ValidateRange(0, 1048576)][int]$PrefixLength = 512
    )

    $Content = [Text.Encoding]::UTF8.GetBytes('static CreateInstall payload')
    $MetadataStream = [IO.MemoryStream]::new()
    $MetadataWriter = [IO.BinaryWriter]::new($MetadataStream, [Text.Encoding]::UTF8, $true)
    try {
      $MetadataWriter.Write([uint16]0)
      $MetadataWriter.Write([long]0)
      $MetadataWriter.Write([uint64]$Content.Length)
      $MetadataWriter.Write([uint64](9 + $Content.Length))
      # GEA stores the running CRC seeded with 0xFFFFFFFF, without CRC32's final XOR.
      $MetadataWriter.Write([uint32]((Get-BinaryCrc32 -Bytes $Content) -bxor [uint32]::MaxValue))
      $MetadataWriter.Write([Text.Encoding]::UTF8.GetBytes('payload.txt'))
      $MetadataWriter.Write([byte]0)
    } finally { $MetadataWriter.Dispose() }
    $Metadata = $MetadataStream.ToArray()
    $HeaderSize = 74 + $Metadata.Length
    $SummarySize = 9 + $Content.Length
    $ArchiveFileSize = $PrefixLength + $HeaderSize + $SummarySize

    $Output = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Output, [Text.Encoding]::UTF8, $true)
    try {
      $Writer.Write([byte[]]::new($PrefixLength))
      $Writer.Write([Text.Encoding]::ASCII.GetBytes("GEA`0"))
      $Writer.Write([uint16]0)
      $Writer.Write([uint32]0x12345678)
      $Writer.Write([byte]2)
      $Writer.Write([byte]0)
      $Writer.Write([long]0)
      $Writer.Write([uint32]0)
      $Writer.Write([uint16]1)
      $Writer.Write([uint32]$HeaderSize)
      $Writer.Write([long]$SummarySize)
      $Writer.Write([uint32]$Metadata.Length)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([uint32]0)
      $Writer.Write([byte]8)
      $Writer.Write([byte]1)
      $Writer.Write([byte]1)
      $Writer.Write([byte]0)
      $Writer.Write($Metadata)
      $Writer.Write([byte]0x80)
      $Writer.Write([uint64]$Content.Length)
      $Writer.Write($Content)
    } finally { $Writer.Dispose() }
    [IO.File]::WriteAllBytes($Path, $Output.ToArray())
  }

  function New-TestCreateInstallMultiVolumeFixture {
    param(
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)][string]$CompanionPath
    )

    $Content = [Text.Encoding]::UTF8.GetBytes('split CreateInstall payload')
    $Block = [IO.MemoryStream]::new()
    $BlockWriter = [IO.BinaryWriter]::new($Block, [Text.Encoding]::UTF8, $true)
    try {
      $BlockWriter.Write([byte]0x80)
      $BlockWriter.Write([uint64]$Content.Length)
      $BlockWriter.Write($Content)
    } finally { $BlockWriter.Dispose() }
    $BlockBytes = $Block.ToArray()
    $Block.Dispose()

    $MetadataStream = [IO.MemoryStream]::new()
    $MetadataWriter = [IO.BinaryWriter]::new($MetadataStream, [Text.Encoding]::UTF8, $true)
    try {
      $MetadataWriter.Write([uint16]0)
      $MetadataWriter.Write([long]0)
      $MetadataWriter.Write([uint64]$Content.Length)
      $MetadataWriter.Write([uint64]$BlockBytes.Length)
      $MetadataWriter.Write([uint32]((Get-BinaryCrc32 -Bytes $Content) -bxor [uint32]::MaxValue))
      $MetadataWriter.Write([Text.Encoding]::UTF8.GetBytes('split.txt'))
      $MetadataWriter.Write([byte]0)
    } finally { $MetadataWriter.Dispose() }
    $Metadata = $MetadataStream.ToArray()
    $MetadataStream.Dispose()

    $Pattern = 'disk%02i.gea'
    $HeaderSize = 73 + [Text.Encoding]::UTF8.GetByteCount($Pattern) + 1 + $Metadata.Length
    $MainDataLength = 5
    $ArchiveFileSize = $HeaderSize + $MainDataLength
    $LastVolumeSize = 10 + $BlockBytes.Length - $MainDataLength
    $UniqueId = [uint32]0x13572468

    $Output = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Output, [Text.Encoding]::UTF8, $true)
    try {
      $Writer.Write([Text.Encoding]::ASCII.GetBytes("GEA`0"))
      $Writer.Write([uint16]0)
      $Writer.Write($UniqueId)
      $Writer.Write([byte]2)
      $Writer.Write([byte]0)
      $Writer.Write([long]0)
      $Writer.Write([uint32]0)
      $Writer.Write([uint16]2)
      $Writer.Write([uint32]$HeaderSize)
      $Writer.Write([long]$BlockBytes.Length)
      $Writer.Write([uint32]$Metadata.Length)
      $Writer.Write([long]$ArchiveFileSize)
      $Writer.Write([long]$LastVolumeSize)
      $Writer.Write([long]$LastVolumeSize)
      $Writer.Write([uint32]0)
      $Writer.Write([byte]8)
      $Writer.Write([byte]1)
      $Writer.Write([byte]1)
      $Writer.Write([Text.Encoding]::UTF8.GetBytes($Pattern))
      $Writer.Write([byte]0)
      $Writer.Write($Metadata)
      $Writer.Write($BlockBytes, 0, $MainDataLength)
    } finally { $Writer.Dispose() }
    [IO.File]::WriteAllBytes($Path, $Output.ToArray())
    $Output.Dispose()

    $Companion = [IO.MemoryStream]::new()
    $CompanionWriter = [IO.BinaryWriter]::new($Companion, [Text.Encoding]::UTF8, $true)
    try {
      $CompanionWriter.Write([Text.Encoding]::ASCII.GetBytes("GEA`0"))
      $CompanionWriter.Write([uint16]1)
      $CompanionWriter.Write($UniqueId)
      $CompanionWriter.Write($BlockBytes, $MainDataLength, $BlockBytes.Length - $MainDataLength)
    } finally { $CompanionWriter.Dispose() }
    [IO.File]::WriteAllBytes($CompanionPath, $Companion.ToArray())
    $Companion.Dispose()
  }
}

Describe 'CreateInstall static parser' {
  It 'Should parse and expand a bounded GEA v2 stored file' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-createinstall.exe'
    $DestinationPath = Join-Path $Script:FixtureDirectory 'createinstall-expanded'
    New-TestCreateInstallFixture -Path $FixturePath
    Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction SilentlyContinue

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath; DestinationPath = $DestinationPath } {
      param($FixturePath, $DestinationPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'requireAdministrator' }
      $Info = Get-CreateInstallInfo -Path $FixturePath
      $Files = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -CollisionAction Rename)

      $Info.GEA.MajorVersion | Should -Be 2
      $Info.GEA.EntryCount | Should -Be 1
      $Info.GEA.CompressionMethods | Should -Be @('Store')
      $Info.Scope | Should -Be 'machine'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.UninstallRegistrations | Should -BeNullOrEmpty
      $Info.CanExpand | Should -BeTrue
      $Files.Name | Should -Be @('payload.txt')
      Get-Content -LiteralPath $Files[0].FullName -Raw | Should -Be 'static CreateInstall payload'
    }
  }

  It 'Should decode a source-backed LZGE order-six regression vector' {
    InModuleScope CreateInstall {
      Import-CreateInstallLzgeDecoder
      # Compressed dlgsets.res block from the external real-installer fixture.
      $Compressed = [Convert]::FromBase64String('SbGuB7oAAABax+/4Rks3R5B1UJUlTtymSUq5CSdFqE7FOjuEfVOqp4HoAdnk1Qzu66kVbwObkpO+52PRlK48jwueFvTzw7nh4btvQ8O6vJ/dHs06vBt13o1vDvvQCzWiROqTeN0Ij3bS6qwwSAQDJYwjAMQvzFaPjeW6fvatqXmx+he4pKKr5aRt0cbRGrvU7MYyzQMogmcs4PQqsFyi1IVV/L1Wxnf/L2i4Ql/L32asbki9hI49IzZkk8TmmbobK6Jtl4WJDX03EypK69jr54v9ArD7XjZ3TfHQpnmaZjG9W9Oo52VMXW+L0eoni7q/3fz1KttSBRXm5LdFfeTkKSql8ESTfmbvi0U1jDMiof4F9dwsqVzn2Rpex+P4Zb/x/ZCYpvcXhA==')
      $Decoded = [Dumplings.Gentee.LzgeDecoder]::Decode($Compressed, 588)

      $Decoded.Length | Should -Be 588
      [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Decoded)) |
        Should -Be 'F28B2E9BAF05FFC72B3059C354EA35A10AA65AE3A574B7110885545699B265CD'
    }
  }

  It 'Should parse a standalone GEA image such as the SETUP_TEMP resource' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-createinstall-standalone.gea'
    New-TestCreateInstallFixture -Path $FixturePath -PrefixLength 0

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      $Layout = Get-CreateInstallArchiveLayout -Path $FixturePath

      $Layout.ArchiveOffset | Should -Be 0
      $Layout.Entries.FullName | Should -Be @('payload.txt')
    }
  }

  It 'Should preserve metadata and safely stream a split GEA volume set' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'split-main.gea'
    $CompanionPath = Join-Path $Script:FixtureDirectory 'disk02.gea'
    $DestinationPath = Join-Path $Script:FixtureDirectory 'split-expanded'
    New-TestCreateInstallMultiVolumeFixture -Path $FixturePath -CompanionPath $CompanionPath

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath; CompanionPath = $CompanionPath; DestinationPath = $DestinationPath } {
      param($FixturePath, $CompanionPath, $DestinationPath)
      Mock Get-PERequestedExecutionLevel { $null }

      $Layout = Get-CreateInstallArchiveLayout -Path $FixturePath
      $Layout.VolumeCount | Should -Be 2
      $Layout.AllVolumesAvailable | Should -BeTrue
      $Layout.DataSegments | Should -HaveCount 2
      $Layout.VolumeFiles[1].VolumeNumber | Should -Be 1
      $Files = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -CollisionAction Error)
      Get-Content -LiteralPath $Files[0].FullName -Raw | Should -Be 'split CreateInstall payload'

      Remove-Item -LiteralPath $CompanionPath -Force
      $Info = Get-CreateInstallInfo -Path $FixturePath
      $Info.GEA.AllVolumesAvailable | Should -BeFalse
      $Info.GEA.MissingVolumes | Should -HaveCount 1
      $Info.CanExpand | Should -BeFalse
      $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Archive.VolumeMissing'
      { Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -CollisionAction Error } | Should -Throw '*companion volume*unavailable*'
    }
  }

  It 'Should reject companion volumes from another GEA archive' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'split-integrity-main.gea'
    $CompanionPath = Join-Path $Script:FixtureDirectory 'disk02.gea'
    New-TestCreateInstallMultiVolumeFixture -Path $FixturePath -CompanionPath $CompanionPath
    $Bytes = [IO.File]::ReadAllBytes($CompanionPath)
    $Bytes[6] = $Bytes[6] -bxor 0xFF
    [IO.File]::WriteAllBytes($CompanionPath, $Bytes)

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      { Get-CreateInstallArchiveLayout -Path $FixturePath } | Should -Throw '*does not belong to this archive*'
    }
  }

  It 'Should classify official CreateInstall <Version> media through structural archive and ARP profiles' -ForEach @(
    @{ Version = '5.9.0'; FixtureName = 'CreateInstall.Builder.5.9.0.exe'; Sha256 = '0FA71D24ED44035B15055A5356CD76BD76D43A16EC136A65F82B00928E91AB15'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 431; WritesNoModify = $false }
    @{ Version = '5.19.1'; FixtureName = 'CreateInstall.Builder.5.19.1.exe'; Sha256 = 'DA515094D2A287CB402FA5B2B551BF668498A24BBC20C543D3E415799E15B06E'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 596; WritesNoModify = $false }
    @{ Version = '6.0.0'; FixtureName = 'CreateInstall.Builder.6.0.0.exe'; Sha256 = '496E27D83EB5AB8FB4228D5D422DAB5FFA0461A81B76580DB71CD57941DDC95D'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 605; WritesNoModify = $false }
    @{ Version = '6.3.3'; FixtureName = 'CreateInstall.Builder.6.3.3.exe'; Sha256 = '3A32FB655FD7A47215B4ADF0350DA1653F6B108260C2212B1164EED5F131EFA6'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Legacy3'; ProductCode = 'CreateInstall'; EntryCount = 623; WritesNoModify = $false }
    @{ Version = '6.4.0'; FixtureName = 'CreateInstall.Builder.6.4.0.exe'; Sha256 = '4B61EA517EE0B5AA1453363E09D3B1036D3A2E261B2A95356D557EAC1C31132E'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Scoped4'; ProductCode = 'CreateInstall'; EntryCount = 635; WritesNoModify = $false }
    @{ Version = '7.0.6'; FixtureName = 'CreateInstall.Builder.7.0.6.exe'; Sha256 = '1243CC0DED031C68E75583F2A7E6FC7AD5CDCA042C621B922E232BC82DC92488'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Scoped4'; ProductCode = 'CreateInstall'; EntryCount = 631; WritesNoModify = $false }
    @{ Version = '7.0.19'; FixtureName = 'CreateInstall.Builder.7.0.19.exe'; Sha256 = '1538F0CC02B5DC9D824471313C7A8919A87CE8F24E19C4C27F5C957B3F871A62'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Scoped4'; ProductCode = 'CreateInstall'; EntryCount = 630; WritesNoModify = $false }
    @{ Version = '7.0.26'; FixtureName = 'CreateInstall.Builder.7.0.26.exe'; Sha256 = '17948F38CFA87BB333DED387CFC89D1BE618C430183985B9DD6EF58B62D5DBE1'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Policy4'; ProductCode = 'CreateInstall'; EntryCount = 630; WritesNoModify = $true }
    @{ Version = '7.1.3'; FixtureName = 'CreateInstall.Builder.7.1.3.exe'; Sha256 = '2A37DE3516E6698B6DAEEB3EB90E691CABD17EC73287F225DC82BA456E78111A'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Policy4'; ProductCode = 'CreateInstall'; EntryCount = 633; WritesNoModify = $true }
    @{ Version = '7.1.7'; FixtureName = 'CreateInstall.Builder.7.1.7.exe'; Sha256 = '9529AF370EC0F3328ABB66D0417CAF49E262D054CEE7B685FEE888C7FAC81C44'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Extended5'; ProductCode = 'CreateInstall'; EntryCount = 635; WritesNoModify = $true }
    @{ Version = '7.4.0'; FixtureName = 'CreateInstall.Builder.7.4.0.exe'; Sha256 = 'E060C09D45F7ACBF929B4BEE7EB892AEBAF7047AFA5AE3D0449EEEABD5AC6766'; ArchiveProfile = 'GEA1'; AddRemoveProfile = 'Extended5'; ProductCode = 'CreateInstall'; EntryCount = 652; WritesNoModify = $true }
    @{ Version = '8.0.1'; FixtureName = 'CreateInstall.Builder.8.0.1.exe'; Sha256 = '1D0105E0066958D478C22CFAB7FA362E6023F487C5B9950E6E4FE4A8744F81A8'; ArchiveProfile = 'GEA2'; AddRemoveProfile = 'Extended5'; ProductCode = 'CreateInstall'; EntryCount = 665; WritesNoModify = $true }
  ) {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $FixtureName)
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because "Cache the official CreateInstall $Version builder fixture."
      return
    }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.DisplayVersion | Should -Be $Version
    $Info.GEA.ArchiveProfile | Should -Be $ArchiveProfile
    $Info.GEA.EntryCount | Should -Be $EntryCount
    $Info.GenteeProgram.VersionMajor | Should -Be 4
    $Info.GenteeProgram.VersionMinor | Should -Be 0
    $Info.GenteeProgram.AddRemoveProfile | Should -Be $AddRemoveProfile
    $Info.InstallGroupRoute | Should -Be ($Version -eq '5.9.0' ? 'Direct5' : 'Extended6')
    $Info.InstalledFiles | Should -HaveCount $EntryCount
    $Info.ProductCode | Should -Be $ProductCode
    $Info.Scope | Should -Be 'machine'
    $Info.UninstallRegistrations | Should -HaveCount 1
    $Info.UninstallRegistrations[0] | Should -Not -BeNullOrEmpty
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\CreateInstall'
    $Info.UninstallString | Should -Be '"%ProgramFiles(x86)%\CreateInstall\uninstall.exe"'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'UninstallString'
    @($Info.RegistryWrites | Where-Object Name -EQ 'NoModify').Count | Should -Be ([int]$WritesNoModify)
    if ($Version -ne '5.9.0') {
      $Info.SupportsSilentInstallation | Should -BeTrue
      $Info.InstallModes | Should -Be @('interactive', 'silent', 'silentWithProgress')
      $Info.InstallerSwitches.Silent | Should -Be '-silent'
      $Info.InstallerSwitches.SilentWithProgress | Should -Be '-silent'
    } else {
      $Info.SupportsSilentInstallation | Should -BeFalse
      $Info.InstallModes | Should -Be @('interactive')
      @($Info.InstallerSwitches.Keys).Count | Should -Be 0
    }
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
  }

  It 'Should let later custom registry values override generated ARP values' {
    InModuleScope CreateInstall {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Generated'; Name = 'DisplayName'; Value = 'Generated name'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Generated'; Name = 'Publisher'; Value = 'Generated publisher'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Generated'; Name = 'DisplayName'; Value = 'Custom name'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'DisplayName'; Value = 'Hidden name'; Type = 'REG_SZ'; IsConditional = $false }
        [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden'; Name = 'SystemComponent'; Value = 1; Type = 'REG_DWORD'; IsConditional = $false }
      )

      $Evidence = Get-CreateInstallArpEvidence -RegistryWrite $Writes

      $Evidence.VisibleEntries | Should -HaveCount 1
      $Evidence.VisibleEntries[0].DisplayName | Should -Be 'Custom name'
      $Evidence.ProductCodes | Should -Be @('Generated')
      $Evidence.Scopes | Should -Be @('machine')
      $Evidence.AppsAndFeaturesEntries | Should -HaveCount 1
      $Evidence.Entries | Should -HaveCount 2
      $Evidence.Diagnostics.Id | Should -Be @('CreateInstall.ARP.Hidden')
    }
  }

  It 'Should promote conditional registry evidence only to fields addressed by its key' {
    InModuleScope CreateInstall {
      Get-CreateInstallRegistryAffectedField -Root HKLM -Key 'Software\Vendor\Product' | Should -BeNullOrEmpty
      Get-CreateInstallRegistryAffectedField -Root HKLM -Key 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Product' | Should -Be @('ProductCode', 'AppsAndFeaturesEntries')
      Get-CreateInstallRegistryAffectedField -Root HKCU -Key 'Software\Classes\.example' | Should -Be @('Protocols', 'FileExtensions')
      Get-CreateInstallRegistryAffectedField -Root HKCU -Key 'Software\#dynamic#' -UnresolvedMacros dynamic | Should -Be @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions')
    }
  }

  It 'Should recover source-backed system operations from stripped Gentee routines' {
    InModuleScope CreateInstall {
      $ListStream = [IO.MemoryStream]::new()
      $ListWriter = [IO.BinaryWriter]::new($ListStream, [Text.Encoding]::UTF8, $true)
      function Add-TestList {
        param([string[][]]$Rows)
        $Offset = [uint32]$ListStream.Position
        $ListWriter.Write([uint32]$Rows.Count)
        foreach ($Row in $Rows) {
          foreach ($Value in $Row) {
            $ListWriter.Write([Text.Encoding]::UTF8.GetBytes($Value))
            $ListWriter.Write([byte]0)
          }
        }
        return $Offset
      }
      $EnvironmentOffset = Add-TestList -Rows (, [string[]]@('DUMPLINGS_CREATEINSTALL', '#setuppath#', '2', '', 'environment evidence'))
      $FontOffset = Add-TestList -Rows (, [string[]]@('#fontpath#', 'evidence.ttf', 'Evidence Font', '1', '', 'font evidence'))
      $ComOffset = Add-TestList -Rows (, [string[]]@('#setuppath#', 'evidence.dll', '1', '', 'comresult', 'COM evidence'))
      $DotNetOffset = Add-TestList -Rows (, [string[]]@('#setuppath#', 'evidence.net.dll', '4', '/tlb', '', '.NET evidence'))
      $ListWriter.Dispose()
      $ListBytes = $ListStream.ToArray()
      $ListStream.Dispose()

      function New-TestCommand {
        param([uint32]$Command, [object]$Operand, [int]$Index)
        [pscustomobject]@{ Command = $Command; Operand = $Operand; Index = $Index; Offset = 0x1000 + $Index }
      }
      function New-TestFunction {
        param([uint32]$Id, [uint32]$ParameterCount, [string]$LiteralText, [object[]]$Commands, [int]$Size = 256, [string[]]$StringLiterals = @(), [object[]]$ExternalCalls = @())
        [pscustomobject]@{ Record = [pscustomobject]@{ Id = $Id; Name = ''; Size = $Size; Offset = $Id; PayloadOffset = 0; EndOffset = 0 }; ParameterCount = $ParameterCount; LiteralText = $LiteralText; Commands = @($Commands); StringLiterals = $StringLiterals; ExternalCalls = $ExternalCalls }
      }

      $CallerCommands = [Collections.Generic.List[object]]::new()
      $AddCommand = { param([uint32]$Command, [object]$Operand) $CallerCommands.Add((New-TestCommand -Command $Command -Operand $Operand -Index $CallerCommands.Count)) }
      & $AddCommand 25 $EnvironmentOffset; & $AddCommand 100 $null
      & $AddCommand 34 'PATH'; & $AddCommand 34 '#setuppath#\bin'; & $AddCommand 25 ([uint32]3); & $AddCommand 34 ''; & $AddCommand 101 $null
      & $AddCommand 34 'PATH'; & $AddCommand 34 '#setuppath#\old'; & $AddCommand 25 ([uint32]1); & $AddCommand 34 ''; & $AddCommand 102 $null
      & $AddCommand 34 'PATH'; & $AddCommand 34 '#setuppath#\unknown'; & $AddCommand 25 ([uint32]2); & $AddCommand 34 ''; & $AddCommand 103 $null
      foreach ($Value in @('x64', '00000101', 'or', 'checkret', 'Visual C++ is required', '')) { & $AddCommand 34 $Value }; & $AddCommand 120 $null
      foreach ($Value in @('#setuppath#', 'service.exe', 'DumplingsService', 'Dumplings Service', 'Parser evidence service')) { & $AddCommand 34 $Value }
      & $AddCommand 25 ([uint32]3); & $AddCommand 25 ([uint32]1); & $AddCommand 34 ''; & $AddCommand 111 $null
      & $AddCommand 25 $FontOffset; & $AddCommand 130 $null
      & $AddCommand 25 $ComOffset; & $AddCommand 131 $null
      & $AddCommand 25 $DotNetOffset; & $AddCommand 132 $null

      $Functions = [Collections.Generic.Dictionary[uint32, object]]::new()
      $Functions[100] = New-TestFunction 100 1 'Environment'
      $Functions[101] = New-TestFunction 101 4 'Environment g_append' @() 256 @('g_append', 'g_append', ';', 'Environment')
      $Functions[102] = New-TestFunction 102 4 'Environment g_append' @() 256 @('g_append', 'Environment', '', 'g_append', 'g_append', ';', 'Environment')
      $Functions[103] = New-TestFunction 103 4 'Environment g_append' @() 256 @('Environment', 'g_append')
      $Functions[110] = New-TestFunction 110 6 'System\CurrentControlSet\Services\'
      $Functions[111] = New-TestFunction 111 7 '' @((New-TestCommand 110 $null 0))
      $Functions[120] = New-TestFunction 120 6 'SOFTWARE\Classes\Installer\Products\ RuntimeMinimum'
      $Functions[130] = New-TestFunction 130 1 'Software\Microsoft\Windows NT\CurrentVersion\Fonts'
      $Functions[131] = New-TestFunction 131 1 '#syspath#\regsvr32.exe /s isdllok'
      $Functions[132] = New-TestFunction 132 1 'RegAsm.exe /s /codebase'
      $Functions[200] = New-TestFunction 200 0 '' $CallerCommands.ToArray() 4096
      $Program = [pscustomobject]@{ FunctionIndex = $Functions }
      $Project = [pscustomobject]@{ Variables = [ordered]@{ setuppath = '#progfiles#\Evidence' }; BufferData = $ListBytes }

      $Environment = Get-CreateInstallEnvironmentEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Prerequisite = Get-CreateInstallPrerequisiteEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Service = Get-CreateInstallServiceEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Registration = Get-CreateInstallRegistrationEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true

      $Environment.EnvironmentChanges | Should -HaveCount 4
      ($Environment.EnvironmentChanges | Where-Object Operation -EQ Set).Value | Should -Be '%ProgramFiles(x86)%\Evidence'
      ($Environment.EnvironmentChanges | Where-Object Operation -EQ Append).Scope | Should -Be 'both'
      ($Environment.EnvironmentChanges | Where-Object Operation -EQ Remove).Value | Should -Be '%ProgramFiles(x86)%\Evidence\old'
      ($Environment.EnvironmentChanges | Where-Object Operation -EQ AppendOrRemove).Scope | Should -Be 'user'
      $Environment.Diagnostics.Id | Should -Contain 'CreateInstall.Environment.AppendDeleteAmbiguous'
      $Prerequisite.PrerequisiteChecks | Should -HaveCount 1
      $Prerequisite.PrerequisiteChecks[0].Versions | Should -Be @('2015', '2019')
      $Prerequisite.PrerequisiteChecks[0].Architecture | Should -Be 'x64'
      $Prerequisite.PrerequisiteChecks[0].PackageDependencyCandidates | Should -Be @('Microsoft.VCRedist.2015+.x64')
      $Service.Services | Should -HaveCount 1
      $Service.Services[0].BinaryPath | Should -Be '%ProgramFiles(x86)%\Evidence\service.exe'
      $Service.Services[0].StartType | Should -Be 'Manual'
      $Service.Services[0].StartAfterInstall | Should -BeFalse
      $Registration.Registrations | Should -HaveCount 3
      $Registration.Registrations.Kind | Should -Be @('Font', 'Com', 'DotNetAssembly')
      ($Registration.Registrations | Where-Object Kind -EQ DotNetAssembly).Framework | Should -Be '.NET Framework 4.x x64'
    }
  }

  It 'Should recover source-backed file, download, task, service, archive, and INI operations' {
    InModuleScope CreateInstall {
      $ListStream = [IO.MemoryStream]::new()
      $ListWriter = [IO.BinaryWriter]::new($ListStream, [Text.Encoding]::UTF8, $true)
      function Add-OperationList {
        param([string[][]]$Rows)
        $Offset = [uint32]$ListStream.Position
        $ListWriter.Write([uint32]$Rows.Count)
        foreach ($Row in $Rows) { foreach ($Value in $Row) { $ListWriter.Write([Text.Encoding]::UTF8.GetBytes($Value)); $ListWriter.Write([byte]0) } }
        return $Offset
      }
      $CopyOffset = Add-OperationList -Rows (, [string[]]@('#exepath#', 'source.dat', '#setuppath#', 'copied.dat', '1', '', 'copy'))
      $DownloadOffset = Add-OperationList -Rows (, [string[]]@('payload.bin', '#setuppath#', 'cache', '', '1', '', 'downloadResult', 'download'))
      $IniSetOffset = Add-OperationList -Rows (, [string[]]@('Theme', 'Dark', '', '0', 'setting'))
      $IniDeleteOffset = Add-OperationList -Rows (, [string[]]@('Legacy', '', 'delete'))
      $ListWriter.Dispose()
      $ListBytes = $ListStream.ToArray()
      $ListStream.Dispose()

      function New-OperationCommand {
        param([uint32]$Command, [object]$Operand, [int]$Index)
        [pscustomobject]@{ Command = $Command; Operand = $Operand; Index = $Index; Offset = 0x4000 + $Index }
      }
      function New-OperationFunction {
        param([uint32]$Id, [uint32]$ParameterCount, [string[]]$StringLiterals = @(), [string[]]$ExternalNames = @(), [object[]]$Commands = @())
        $ExternalCalls = @($ExternalNames | ForEach-Object { [pscustomobject]@{ Name = $_; Library = 'fixture.dll' } })
        [pscustomobject]@{ Record = [pscustomobject]@{ Id = $Id; Name = ''; Size = 256; Offset = $Id; PayloadOffset = 0; EndOffset = 0 }; ParameterCount = $ParameterCount; LiteralText = $StringLiterals -join ' '; StringLiterals = $StringLiterals; ExternalCalls = $ExternalCalls; Commands = @($Commands) }
      }
      $CallerCommands = [Collections.Generic.List[object]]::new()
      $AddCommand = { param([uint32]$Command, [object]$Operand) $CallerCommands.Add((New-OperationCommand -Command $Command -Operand $Operand -Index $CallerCommands.Count)) }

      foreach ($Value in @('#username#', 'Evidence Task', '#setuppath#', 'task.exe', '--run', '#setuppath#', 'work', 'Task comment')) { & $AddCommand 34 $Value }
      & $AddCommand 25 ([uint32]1)
      foreach ($Value in @('+2', '1', '', '')) { & $AddCommand 34 $Value }
      & $AddCommand 300 $null
      & $AddCommand 34 'Old Task'; & $AddCommand 34 ''; & $AddCommand 301 $null
      foreach ($Value in @('#exepath#', 'source.dat', '#setuppath#', 'direct.dat')) { & $AddCommand 34 $Value }
      & $AddCommand 25 ([uint32]1); & $AddCommand 25 ([uint32]3); & $AddCommand 34 ''; & $AddCommand 302 $null
      & $AddCommand 25 $CopyOffset; & $AddCommand 303 $null
      & $AddCommand 34 'https://downloads.example.test/base'; & $AddCommand 25 $DownloadOffset; & $AddCommand 25 ([uint32]1); & $AddCommand 304 $null
      foreach ($Value in @('#setuppath#', 'payload.7z', '#setuppath#', 'seven', '', '*.exe', '*.pdb')) { & $AddCommand 34 $Value }
      & $AddCommand 25 ([uint32]2); & $AddCommand 305 $null
      foreach ($Value in @('#setuppath#', 'payload.cab', '#setuppath#', 'cabinet', '', '*.*')) { & $AddCommand 34 $Value }
      & $AddCommand 25 ([uint32]2); & $AddCommand 306 $null
      foreach ($Value in @('#setuppath#', 'payload.zip', '#setuppath#', 'zip', '')) { & $AddCommand 34 $Value }
      & $AddCommand 25 ([uint32]516); & $AddCommand 307 $null
      foreach ($Value in @('#setuppath#', 'settings.ini', 'General')) { & $AddCommand 34 $Value }
      & $AddCommand 25 $IniSetOffset; & $AddCommand 25 ([uint32]1); & $AddCommand 25 ([uint32]1); & $AddCommand 308 $null
      foreach ($Value in @('#setuppath#', 'settings.ini', 'General')) { & $AddCommand 34 $Value }
      & $AddCommand 25 $IniDeleteOffset; & $AddCommand 25 ([uint32]1); & $AddCommand 25 ([uint32]1); & $AddCommand 309 $null
      & $AddCommand 34 ''; & $AddCommand 34 'EvidenceService'; & $AddCommand 310 $null
      & $AddCommand 34 ''; & $AddCommand 34 'EvidenceService'; & $AddCommand 311 $null
      & $AddCommand 34 ''; & $AddCommand 34 'EvidenceService'; & $AddCommand 312 $null

      $Functions = [Collections.Generic.Dictionary[uint32, object]]::new()
      $Functions[300] = New-OperationFunction -Id 300 -ParameterCount 11 -ExternalNames newtask
      $Functions[301] = New-OperationFunction -Id 301 -ParameterCount 2 -ExternalNames deltask
      $Functions[302] = New-OperationFunction -Id 302 -ParameterCount 5 -StringLiterals @('errdir', 'errfile', 'ginst_dir', 'ginst_file')
      $Functions[303] = New-OperationFunction -Id 303 -ParameterCount 1 -StringLiterals reboot
      $Functions[304] = New-OperationFunction -Id 304 -ParameterCount 3 -StringLiterals @('#download#', 'dwn_progsize', 'Pdownloads')
      $Functions[305] = New-OperationFunction -Id 305 -ParameterCount 6 -StringLiterals @('result7z', 'Decompressing error while reading archive')
      $Functions[306] = New-OperationFunction -Id 306 -ParameterCount 5 -StringLiterals @('input is not a cabinet archive!', 'ginst_dir', 'ginst_file')
      $Functions[307] = New-OperationFunction -Id 307 -ParameterCount 4 -StringLiterals @('decompzip.vbs', 'Shell.Application')
      $Functions[308] = New-OperationFunction -Id 308 -ParameterCount 5 -ExternalNames @('GetPrivateProfileStringW', 'WritePrivateProfileStringW')
      $Functions[309] = New-OperationFunction -Id 309 -ParameterCount 5 -ExternalNames WritePrivateProfileStringW
      $Functions[310] = New-OperationFunction -Id 310 -ParameterCount 1 -ExternalNames StartServiceW
      $Functions[311] = New-OperationFunction -Id 311 -ParameterCount 1 -ExternalNames ControlService
      $Functions[312] = New-OperationFunction -Id 312 -ParameterCount 1 -ExternalNames DeleteService
      $Functions[400] = New-OperationFunction -Id 400 -ParameterCount 0 -Commands ($CallerCommands.ToArray())
      $Program = [pscustomobject]@{ FunctionIndex = $Functions }
      $Project = [pscustomobject]@{ Variables = [ordered]@{ setuppath = '#progfiles#\Evidence'; exepath = 'C:\Setup'; username = 'FixtureUser' }; BufferData = $ListBytes }

      $Tasks = Get-CreateInstallScheduledTaskEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Files = Get-CreateInstallFileOperationEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Downloads = Get-CreateInstallDownloadEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Archives = Get-CreateInstallArchiveOperationEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Configuration = Get-CreateInstallConfigurationEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true
      $Services = Get-CreateInstallServiceEvidence -Program $Program -ProjectVariableEvidence $Project -Is32Bit $true

      $Tasks.ScheduledTasks.Operation | Should -Be @('Create', 'Delete')
      $Tasks.ScheduledTasks[0].Executable | Should -Be '%ProgramFiles(x86)%\Evidence\task.exe'
      $Files.FileOperations.Route | Should -Be @('Direct', 'List')
      $Files.FileOperations[1].Destination | Should -Be '%ProgramFiles(x86)%\Evidence\copied.dat'
      $Downloads.Downloads[0].Url | Should -Be 'https://downloads.example.test/base/payload.bin'
      $Downloads.Downloads[0].Destination | Should -Be '%ProgramFiles(x86)%\Evidence\cache\payload.bin'
      $Archives.ArchiveOperations.Format | Should -Be @('7z', 'Cabinet', 'ZIP')
      $Configuration.ConfigurationChanges.Operation | Should -Be @('Set', 'Delete')
      $Configuration.ConfigurationChanges[0].FilePath | Should -Be '%ProgramFiles(x86)%\Evidence\settings.ini'
      $Services.Services.Operation | Should -Be @('Start', 'Stop', 'Delete')
    }
  }

  It 'Should expand a GEA1 LZGE payload from the oldest cached builder' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CreateInstall.Builder.5.9.0.exe')
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 '0FA71D24ED44035B15055A5356CD76BD76D43A16EC136A65F82B00928E91AB15')) {
      Set-ItResult -Skipped -Because 'Cache the official CreateInstall 5.9.0 builder fixture.'
      return
    }
    $DestinationPath = Join-Path $TestDrive 'createinstall-gea1-expanded'

    $Files = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'close.gt' -CollisionAction Error)

    $Files | Should -HaveCount 1
    $Files[0].Length | Should -Be 1215
    (Get-FileHash -LiteralPath $Files[0].FullName -Algorithm SHA256).Hash | Should -Be 'F2C22B0F121E3F2973EBB67FC0D4F9B68E8681CD8A4B855334EA44E12A68C98F'
  }

  It 'Should reject pre-CreateInstall Gentee Installer media rather than weaken GEA detection' -ForEach @(
    @{ Name = 'CreateInstall.Predecessor.ci2000.exe'; Sha256 = '64D04E194898BE7604E374D2AB545AE73DFF336132AE2F2A8D9A4002F648C461' }
    @{ Name = 'CreateInstall.Predecessor.setupgen.exe'; Sha256 = 'F6E425BAFB7057592E631F0D4267CBC5112520A32B2AAE2957DF0BE0405055AE' }
    @{ Name = 'CreateInstall.Predecessor.sgpro.exe'; Sha256 = '2A4C129B04490E66CB40C9C0F57DFA8FE83E4BD5DEA211D911066FC3A90A6E19' }
  ) {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name)
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 $Sha256)) { Set-ItResult -Skipped -Because "Cache the predecessor fixture $Name."; return }

    Test-CreateInstall -Path $FixturePath | Should -BeFalse
  }

  It 'Should derive Balabolka ARP identity from its compiled addremoveext call' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CrossPlusA.Balabolka.setup.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'Balabolka'
    $Info.ProductCodeEvidence | Should -Match '^Deterministic CreateInstall uninstall registry writes:'
    $Info.GEA.ArchiveProfile | Should -Be 'GEA2'
    $Info.GenteeProgram.AddRemoveProfile | Should -Be 'Extended5'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.UninstallKeyName | Should -Be @('Balabolka')
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Balabolka'
    $Info.UninstallString | Should -Be '"%ProgramFiles(x86)%\Balabolka\uninstall.exe"'
    $Info.FileExtensions | Should -Be @('bxt', 'bxz')
    $Info.PayloadArchitectures | Should -Be @('x86')
    $Info.PayloadAnalysisFiles | Should -Contain '%ProgramFiles(x86)%\Balabolka\balabolka.exe'
    $Info.PayloadDependencyInfo.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.x86'
    $Info.GEA.UnsupportedCompressionMethods | Should -Not -Contain 'PPMd'
    $Info.ConfigurationChanges | Should -HaveCount 6
    @($Info.ConfigurationChanges.FilePath | Sort-Object -Unique) | Should -Be @('%APPDATA%\Balabolka\balabolka.cfg')
    $Info.ConfigurationChanges.Key | Should -Contain 'MinimizeToTray'
    $Info.CanExpand | Should -BeTrue
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.InstallGroup.ConditionDynamic'
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Shortcut.Conditional'
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Run.Conditional'
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Registry.Conditional'
    $RegistryDiagnostic = $Info.Diagnostics | Where-Object Id -EQ 'CreateInstall.Registry.Conditional'
    $RegistryDiagnostic.AffectedFields | Should -BeNullOrEmpty
    $Info.PrerequisiteChecks | Should -HaveCount 1
    $Info.PrerequisiteChecks[0].Versions | Should -Be @('2019')
    $Info.PrerequisiteChecks[0].PackageDependencyCandidates | Should -Be @('Microsoft.VCRedist.2015+.x86')
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
    $Expression = @($Info.GenteeExpressions | Where-Object { $_.Operation -eq 'InstallGroup' -and $_.Expression -ceq '@if73_used' })
    $Expression | Should -HaveCount 1
    $Expression[0].ExpressionKind | Should -Be 'FunctionCondition'
    $Expression[0].RequiresReview | Should -BeTrue
    $Expression[0].FunctionFound | Should -BeTrue
    $Expression[0].ReferencedFunction.Name | Should -Be 'if73_used'
    $Expression[0].ReferencedFunction.CommandsTruncated | Should -BeFalse
    $Expression[0].ReferencedFunction.LiteralStrings | Should -Contain 'oswindows'
    $RuntimeVariable = @($Expression[0].Variables | Where-Object Name -EQ 'oswindows')
    $RuntimeVariable | Should -HaveCount 1
    $RuntimeVariable[0].Source | Should -Be 'RuntimeOrUnknown'
    $RuntimeVariable[0].IsDefined | Should -BeFalse
  }

  It 'Should expand source-backed PPMd and solid-continuation payloads from Balabolka' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CrossPlusA.Balabolka.setup.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }
    $DestinationPath = Join-Path $Script:FixtureDirectory 'createinstall-ppmd-expanded'
    Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction SilentlyContinue

    $Wave = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'clipboard.wav' -CollisionAction Rename)
    $Wave.Length | Should -Be 1
    $Wave[0].Length | Should -Be 10328
    (Get-FileHash -LiteralPath $Wave[0].FullName -Algorithm SHA256).Hash |
      Should -Be 'B2391C7751F6EC3296650D6D15C280DA53B6266E2BF5DEEF15DD729C7DA745ED'

    # This executable spans one model-initializing block and six order-1 continuation blocks,
    # exercising allocator exhaustion and the source-matched glue pass.
    $Executable = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'balabolka.exe' -CollisionAction Rename)
    $Executable.Length | Should -Be 1
    $Executable[0].Length | Should -Be 12807680
    (Get-FileHash -LiteralPath $Executable[0].FullName -Algorithm SHA256).Hash |
      Should -Be '0F1312B1A343A0999A854D32E86CC07A5AC3E46F1883021404D9E44D1D9BB58B'
  }

  It 'Should reject physical and declared GEA PPMd truncation without reading adjacent bytes' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CrossPlusA.Balabolka.setup.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }

    InModuleScope CreateInstall -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      $Layout = Get-CreateInstallArchiveLayout -Path $FixturePath
      $Entry = $Layout.Entries | Where-Object FullName -EQ 'clipboard.wav' | Select-Object -First 1
      $Block = @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry)[0]
      $InputBytes = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $Block.DataOffset -Count ([int]$Block.CompressedSize)
      $Truncated = [byte[]]::new($InputBytes.Length - 1)
      [Array]::Copy($InputBytes, $Truncated, $Truncated.Length)
      Import-CreateInstallPpmdDecoder
      $Decoder = [SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder]::new(
        [int]([uint32]$Layout.MemoryMegabytes * 1MB)
      )
      try {
        $InputStream = [IO.MemoryStream]::new($Truncated, $false)
        try {
          { $Decoder.DecodeBlock($InputStream, $Truncated.Length, [int]$Block.OutputSize, $Block.CompressionOrder) } |
            Should -Throw '*PPMd*'
        } finally { $InputStream.Dispose() }
      } finally { $Decoder.Dispose() }

      # Keep the omitted byte physically available but outside the declared range. This models the
      # CreateInstall extractor's read-ahead cache and proves the provider does not cross the GEA
      # record boundary to make a malformed compressed size appear valid.
      $Decoder = [SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder]::new(
        [int]([uint32]$Layout.MemoryMegabytes * 1MB)
      )
      try {
        $InputStream = [IO.MemoryStream]::new($InputBytes, $false)
        try {
          { $Decoder.DecodeBlock($InputStream, $InputBytes.Length - 1, [int]$Block.OutputSize, $Block.CompressionOrder) } |
            Should -Throw '*PPMd*'
          $InputStream.Position | Should -BeLessOrEqual ($InputBytes.Length - 1)
        } finally { $InputStream.Dispose() }
      } finally { $Decoder.Dispose() }
    }
  }

  It 'Should derive the builder ARP identity without package-specific rules' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Novostrim.CreateInstall.8.11.2.exe')
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official CreateInstall builder fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'CreateInstall'
    $Info.GEA.ArchiveProfile | Should -Be 'GEA2'
    $Info.GenteeProgram.AddRemoveProfile | Should -Be 'Extended5'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.Count | Should -Be 1
    $Info.FileExtensions | Should -Be @('ci', 'ciq')
    $Info.InstallerSwitches.Silent | Should -Be '-silent'
    @($Info.Shortcuts | Where-Object Route -EQ 'List') | Should -HaveCount 4
    $Info.Shortcuts.ShortcutPath | Should -Contain '%APPDATA%\Microsoft\Windows\Start Menu\Programs\CreateInstall\Quick CreateInstall.lnk'
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
  }

  It 'Should decode source-generated MSI child execution without relying on function names' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CreateInstall.Generated.RunMsi.exe')
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 'B69078BDE20EC7166AF55650B459D95F8E0449BF2D03B5968D16CC94B48CE39D')) { Set-ItResult -Skipped -Because 'Cache the source-generated CreateInstall Run MSI fixture.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath
    $MsiRuns = @($Info.ExecutedPayloads | Where-Object Kind -EQ 'Msi')
    $ExecutableRuns = @($Info.ExecutedPayloads | Where-Object Kind -EQ 'Executable')

    $ExecutableRuns | Should -HaveCount 1
    $ExecutableRuns[0].Executable | Should -Be 'notepad.exe'
    $MsiRuns | Should -HaveCount 2
    $MsiRuns.MsiFlags | Should -Be @(10, 10)
    $MsiRuns.MsiAction | Should -Be @('Install', 'Install')
    $MsiRuns.NestedInstallerPath | Should -Be @('%ProgramFiles(x86)%\Wait for event\probe.msi', '%ProgramFiles(x86)%\Wait for event\probe.msi')
    $MsiRuns.Arguments | Should -Be @('/l* "%TEMP%\probe.log" /i "%ProgramFiles(x86)%\Wait for event\probe.msi" /quiet /norestart', '/l* "%TEMP%\probe.log" /i "%ProgramFiles(x86)%\Wait for event\probe.msi" /quiet /norestart')
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'
  }

  It 'Should distinguish source-generated environment append and delete routines' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CreateInstall.Generated.Environment.exe')
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 '9B058C3E93219A4A6366D37190CFD135762C5F1EF0EF10E002EEE8712FDB05B3')) { Set-ItResult -Skipped -Because 'Cache the source-generated CreateInstall environment-operation fixture.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.EnvironmentChanges | Should -HaveCount 2
    $Info.EnvironmentChanges.Operation | Should -Be @('Append', 'Remove')
    $Info.EnvironmentChanges.Value | Should -Be @('%ProgramFiles(x86)%\Dumplings CreateInstall Machine\append', '%ProgramFiles(x86)%\Dumplings CreateInstall Machine\delete')
    $Info.EnvironmentChanges.Scope | Should -Be @('both', 'both')
    $Info.Diagnostics.Id | Should -Not -Contain 'CreateInstall.Environment.AppendDeleteAmbiguous'
  }

  It 'Should accept a source-generated no-payload project without fabricating an archive' {
    $FixturePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'CreateInstall.Generated.NoPayload.exe')
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $FixturePath -Sha256 '7E961D905C07BFF8E4AFFE4DBC2AD20D51BC11D44E91E27A07C06988FE0BF14E')) { Set-ItResult -Skipped -Because 'Cache the source-generated CreateInstall no-payload fixture.'; return }

    Test-CreateInstall -Path $FixturePath | Should -BeTrue
    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.GEA | Should -BeNullOrEmpty
    $Info.ExtractedFiles | Should -BeNullOrEmpty
    $Info.CanExpand | Should -BeFalse
    $Info.Diagnostics.Id | Should -Contain 'CreateInstall.Archive.Absent'
    $Info.Diagnostics.Kind | Should -Not -Contain 'Invalid'

    $Analysis = Get-WinGetInstallerAnalysis -Path $FixturePath
    $Analysis.DetectedFamilies.Family | Should -Contain 'CreateInstall'
    $Analysis.SuggestedManifestFields.InstallerType | Should -Be 'exe'
    $Analysis.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'InstallerSwitches'
    $Analysis.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'Scope'
  }

  It 'Should validate the GE header CRC the way the reference ge_load does' {
    InModuleScope CreateInstall {
      function New-TestGenteeProgram {
        param([Nullable[uint32]]$StoredCrc)
        # One resource record (type 9, GHCOM_PACK set) with four zero payload bytes; the record
        # size covers its own five-byte prefix, the size byte, and the payload.
        $Record = [byte[]](9, 0x02, 0, 0, 0, 10) + [byte[]]::new(4)
        $ProgramSize = 22 + $Record.Length
        $Bytes = [byte[]]::new($ProgramSize)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x00004547), 0, $Bytes, 0, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]22), 0, $Bytes, 12, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]$ProgramSize), 0, $Bytes, 16, 4)
        $Bytes[20] = 4
        [Array]::Copy($Record, 0, $Bytes, 22, $Record.Length)
        # Gentee's crc() seeds 0xFFFFFFFF and applies no final XOR, so invert the standard CRC32.
        $Actual = if ($null -ne $StoredCrc) { $StoredCrc } else { (Get-BinaryCrc32 -Bytes $Bytes -Offset 12) -bxor [uint32]::MaxValue }
        [Array]::Copy([BitConverter]::GetBytes([uint32]$Actual), 0, $Bytes, 8, 4)
        return $Bytes
      }

      $ValidProgram = New-TestGenteeProgram
      { Get-CreateInstallGenteeRecord -Bytes $ValidProgram } | Should -Not -Throw
      $Records = Get-CreateInstallGenteeRecord -Bytes $ValidProgram
      $Records.Count | Should -Be 1
      $Records[0].Type | Should -Be 9

      $CorruptProgram = New-TestGenteeProgram -StoredCrc ([uint32]0x12345678)
      { Get-CreateInstallGenteeRecord -Bytes $CorruptProgram } | Should -Throw '*header CRC*'
    }
  }
}
