BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallAware.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PaquetBuilder.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'QSetup.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'DeployMaster.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'CreateInstall.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallMate.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\AdditionalGenericExeParsers'

  function ConvertTo-TestQSetupRecord {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Content, [switch]$Required)
    $RequiredMarker = if ($Required) { '*' } else { '' }
    $Header = [Text.Encoding]::ASCII.GetBytes("|$Name$RequiredMarker|123456|")
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try { $Encoder.Write($Header, 0, $Header.Length); $Encoder.Write($Content, 0, $Content.Length) } finally { $Encoder.Dispose() }
    return [BitConverter]::GetBytes([uint32]$Compressed.Length) + $Compressed.ToArray()
  }

  function New-TestCreateInstallFixture {
    param([Parameter(Mandatory)][string]$Path)

    $Content = [Text.Encoding]::UTF8.GetBytes('static CreateInstall payload')
    $MetadataStream = [IO.MemoryStream]::new()
    $MetadataWriter = [IO.BinaryWriter]::new($MetadataStream, [Text.Encoding]::UTF8, $true)
    try {
      $MetadataWriter.Write([uint16]0)
      $MetadataWriter.Write([long]0)
      $MetadataWriter.Write([uint64]$Content.Length)
      $MetadataWriter.Write([uint64](9 + $Content.Length))
      $MetadataWriter.Write([uint32]0)
      $MetadataWriter.Write([Text.Encoding]::UTF8.GetBytes('payload.txt'))
      $MetadataWriter.Write([byte]0)
    } finally { $MetadataWriter.Dispose() }
    $Metadata = $MetadataStream.ToArray()
    $HeaderSize = 74 + $Metadata.Length
    $SummarySize = 9 + $Content.Length
    $ArchiveFileSize = 512 + $HeaderSize + $SummarySize

    $Output = [IO.MemoryStream]::new()
    $Writer = [IO.BinaryWriter]::new($Output, [Text.Encoding]::UTF8, $true)
    try {
      $Writer.Write([byte[]]::new(512))
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
}

Describe 'InstallAware static parser' {
  It 'Should require InstallAware project evidence in a validated embedded 7z' {
    $ArchiveBytes = [Convert]::FromBase64String('N3q8ryccAASC6rZeGQAAAAAAAABqAAAAAAAAAIO0oUEBABTvu79NWiBzeW50aGV0aWMgc2V0dXAAAQQGAAEJGQAHCwEAASEhAQAMFQAICgEliOZUAAAFARkMAAAAAAAAAAAAAAAAESUARQB4AGEAbQBwAGwAZQBfAFMAZQB0AHUAcAAuAGUAeABlAAAAFAoBALa5/FNLEN0BFQYBACAAAAAAAA==')
    $FixturePath = Join-Path $Script:FixtureDirectory 'installaware-archive.bin'
    [IO.File]::WriteAllBytes($FixturePath, ([byte[]]::new(1024) + $ArchiveBytes))

    InModuleScope InstallAware -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $ArchiveData = Get-InstallAwareArchiveData -Path $FixturePath
      try {
        $ArchiveData.Range.Offset | Should -Be 1024
        $ArchiveData.Entries.FullName | Should -Contain 'Example_Setup.exe'
      } finally { Remove-Item -LiteralPath $ArchiveData.ArchivePath -Force -ErrorAction SilentlyContinue }
    }
  }
}

Describe 'Paquet Builder static parser' {
  It 'Should classify independent payload and runtime archives' {
    $PayloadBytes = [Convert]::FromBase64String('N3q8ryccAAQ9qmANEQAAAAAAAABaAAAAAAAAAMFZj+oBAAzvu79NWiBwYXlsb2FkAAEEBgABCREABwsBAAEhIQEADA0ACAoBlIuc5QAABQEZDAAAAAAAAAAAAAAAABERAGEAcABwAC4AZQB4AGUAAAAZAgAAFAoBAB62AVRLEN0BFQYBACAAAAAAAA==')
    $RuntimeBytes = [Convert]::FromBase64String('N3q8ryccAARvFqxziQAAAAAAAAAhAAAAAAAAAIeEEHoBABHvu79NWiBjb3Jl77u/cHJvcHMAAACBMweuD89dLwwHyEN/QbH6/eXHfeltPRF+KAQ4jdN8i3B2bHASkmtshsURP/CTxIVxKBlS3RJpSTQfS1uagxDwitrxEOECC63BwAFZFPCO/UlgqXK0gK4zcbXJH8lrfwIF5lsbjlRuLVrCC1IqcmXAABcGFgEJcwAHCwEAASMDAQEFXQAQAAAMgIYKASqU5xkAAA==')
    $FixturePath = Join-Path $Script:FixtureDirectory 'paquet-archives.bin'
    [IO.File]::WriteAllBytes($FixturePath, ([byte[]]::new(2048) + $PayloadBytes + [byte[]]::new(73) + $RuntimeBytes))

    InModuleScope PaquetBuilder -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $ArchiveData = Get-PaquetBuilderArchiveData -Path $FixturePath
      try {
        $ArchiveData.Payload.Entries.FullName | Should -Be @('app.exe')
        $ArchiveData.Runtime.Entries.FullName | Should -Contain 'pbfprop.dat'
        $ArchiveData.Runtime.Entries.FullName | Should -Contain 'PBCore64.dll'
      } finally {
        Remove-Item -LiteralPath $ArchiveData.Payload.ArchivePath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ArchiveData.Runtime.ArchivePath -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

Describe 'QSetup static parser' {
  It 'Should parse explicit Setup.txt ARP, scope, architecture, and association directives' {
    $SetupText = @'
SET_PROG_NAME(Example QSetup Product);
SET_PROJECT_NAME(ExampleProject);
SET_PROG_VERSION(4.5.6);
SET_COMPANY_NAME(Example Publisher);
SET_COMPOSER_BUILD(12.0.0.5);
SET_TARGET_DIR(<ProgramFiles>\Example);
SET_PROG_EXE_NAME(<Application Folder>\Example.exe);
SET_CREATE_UNINSTALL;
SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS;
SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME(Example QSetup ARP);
SET_ALL_USERS;
SET_ALLOWED_OS(10.64,11.64);
SET_ADD_ASSOCIATION_ITEM(|Example.Document|Example document|.example|Example|<Application Folder>\Example.exe|<Application Folder>\Example.exe|0|Create|Remove||);
'@
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath

      $Info.DisplayName | Should -Be 'Example QSetup ARP'
      $Info.DisplayVersion | Should -Be '4.5.6'
      $Info.Publisher | Should -Be 'Example Publisher'
      $Info.ProductCode | Should -Be 'Example QSetup ARP'
      $Info.Scope | Should -Be 'machine'
      $Info.SupportedArchitectures | Should -Be @('x64')
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.FileExtensions | Should -Be @('example')
      $Info.Records.Name | Should -Be @('Engine.exe', 'Setup.txt')
    }
  }
}

Describe 'DeployMaster static parser' {
  It 'Should detect transformed payload headers and fail expansion deterministically' {
    $Properties = [byte[]](0x5D, 0x00, 0x00, 0x40, 0x00)
    $RawSizeValue = [uint64]::Parse('8000000000000FFE', [Globalization.NumberStyles]::HexNumber)
    $RawSize = [BitConverter]::GetBytes($RawSizeValue)
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-deploymaster.exe'
    [IO.File]::WriteAllBytes($FixturePath, ([byte[]]::new(1024) + $Properties + $RawSize + [byte[]](0xE3, 1, 2, 3)))

    InModuleScope DeployMaster -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 1024 }
      Mock Get-PERequestedExecutionLevel { 'asInvoker' }
      $Info = Get-DeployMasterInfo -Path $FixturePath

      $Info.OverlayInfo.DictionarySize | Should -Be 4194304
      $Info.OverlayInfo.DeclaredSize | Should -Be 4094
      $Info.OverlayInfo.HasTransformFlag | Should -BeTrue
      $Info.CanExpand | Should -BeFalse
      { Expand-DeployMasterInstaller -Path $FixturePath } | Should -Throw '*unsupported transformed LZMA-like stream*'
    }
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
      $Files = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath)

      $Info.GEA.MajorVersion | Should -Be 2
      $Info.GEA.EntryCount | Should -Be 1
      $Info.GEA.CompressionMethods | Should -Be @('Store')
      $Info.Scope | Should -Be 'machine'
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
}

Describe 'InstallMate static parser' {
  It 'Should map documented PE execution levels to InstallMate scope behavior' {
    InModuleScope InstallMate {
      $Required = Get-InstallMateScopeInfo -RequestedExecutionLevel requireAdministrator
      $Highest = Get-InstallMateScopeInfo -RequestedExecutionLevel highestAvailable
      $Invoker = Get-InstallMateScopeInfo -RequestedExecutionLevel asInvoker

      $Required.Scope | Should -Be 'machine'
      $Required.SupportedScopes | Should -Be @('machine')
      $Highest.SupportedScopes | Should -Be @('user', 'machine')
      $Highest.SupportsDualScope | Should -BeTrue
      $Invoker.DefaultScope | Should -Be 'user'
      $Invoker.SupportedScopes | Should -Be @('user', 'machine')
    }
  }

  It 'Should validate a bounded tiz3 header and reject unsupported expansion' {
    $Bytes = [byte[]]::new(2048)
    [Text.Encoding]::ASCII.GetBytes('tiz3').CopyTo($Bytes, 1024)
    [BitConverter]::GetBytes([uint16]12).CopyTo($Bytes, 1028)
    [BitConverter]::GetBytes([uint16]11).CopyTo($Bytes, 1030)
    [BitConverter]::GetBytes([uint64]1024).CopyTo($Bytes, 1040)
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-installmate.exe'
    [IO.File]::WriteAllBytes($FixturePath, $Bytes)

    InModuleScope InstallMate -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 0; Size = 0 } } } }
      Mock Get-PEOverlayOffset { 1024 }
      Mock Get-PERequestedExecutionLevel { 'highestAvailable' }
      Mock Get-PEVersionStringTable { [pscustomobject]@{ ProductCode = '{11111111-2222-3333-4444-555555555555}'; PackageCode = '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}' } }
      $Info = Get-InstallMateInfo -Path $FixturePath

      $Info.ArchiveInfo.Signature | Should -Be 'tiz3'
      $Info.ArchiveInfo.FormatVersion | Should -Be '12.11'
      $Info.ProductCode | Should -Be '{11111111-2222-3333-4444-555555555555}'
      $Info.ProductCodeEvidence | Should -BeLike '*StringFileInfo.ProductCode*'
      $Info.PackageCode | Should -Be '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
      $Info.Scope | Should -BeNullOrEmpty
      $Info.SupportedScopes | Should -Be @('user', 'machine')
      $Info.SupportsDualScope | Should -BeTrue
      $Info.ScopeConfidence | Should -Be 'conditional'
      $Info.CanExpand | Should -BeFalse
      { Expand-InstallMateInstaller -Path $FixturePath } | Should -Throw '*extraction is not implemented*'
    }
  }
}
