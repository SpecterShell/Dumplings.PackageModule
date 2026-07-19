BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Compression', 'Archive', 'PE', 'RegistryAssociations', 'CreateInstall')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\AdditionalGenericExeParsers'

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

  It 'Should derive Balabolka ARP identity from its compiled addremoveext call' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'CrossPlusA.Balabolka.setup.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'Balabolka'
    $Info.ProductCodeEvidence | Should -Be 'Compiled Gentee addremoveext uninstall-key argument'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.UninstallKeyName | Should -Be @('Balabolka')
    $Info.GEA.UnsupportedCompressionMethods | Should -Not -Contain 'PPMd'
    $Info.CanExpand | Should -BeTrue
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should expand source-backed PPMd and solid-continuation payloads from Balabolka' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'CrossPlusA.Balabolka.setup.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official Balabolka CreateInstall fixture is not cached.'; return }
    $DestinationPath = Join-Path $Script:FixtureDirectory 'createinstall-ppmd-expanded'
    Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction SilentlyContinue

    $Wave = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'clipboard.wav')
    $Wave.Length | Should -Be 1
    $Wave[0].Length | Should -Be 10328
    (Get-FileHash -LiteralPath $Wave[0].FullName -Algorithm SHA256).Hash |
      Should -Be 'B2391C7751F6EC3296650D6D15C280DA53B6266E2BF5DEEF15DD729C7DA745ED'

    # This executable spans one model-initializing block and six order-1 continuation blocks,
    # exercising allocator exhaustion and the source-matched glue pass.
    $Executable = @(Expand-CreateInstallInstaller -Path $FixturePath -DestinationPath $DestinationPath -Name 'balabolka.exe')
    $Executable.Length | Should -Be 1
    $Executable[0].Length | Should -Be 12807680
    (Get-FileHash -LiteralPath $Executable[0].FullName -Algorithm SHA256).Hash |
      Should -Be '0F1312B1A343A0999A854D32E86CC07A5AC3E46F1883021404D9E44D1D9BB58B'
  }

  It 'Should reject physical and declared GEA PPMd truncation without reading adjacent bytes' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'CrossPlusA.Balabolka.setup.exe'
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
    $FixturePath = Join-Path $Script:FixtureDirectory 'Novostrim.CreateInstall.8.11.2.exe'
    if (-not (Test-Path -LiteralPath $FixturePath)) { Set-ItResult -Skipped -Because 'The official CreateInstall builder fixture is not cached.'; return }

    $Info = Get-CreateInstallInfo -Path $FixturePath

    $Info.ProductCode | Should -Be 'CreateInstall'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UninstallRegistrations.Count | Should -Be 1
    $Info.Warnings | Should -BeNullOrEmpty
  }
}
