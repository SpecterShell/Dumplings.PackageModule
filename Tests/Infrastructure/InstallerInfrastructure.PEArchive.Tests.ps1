. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallerInfrastructureTestSetup.ps1')

Describe 'Get-PEVersionStringTable' {
  It 'parses named StringFileInfo values from a PE version resource' {
    $ExecutablePath = (Get-Process -Id $PID).Path
    $VersionStrings = Get-PEVersionStringTable -Path $ExecutablePath

    $VersionStrings.ProductName | Should -Not -BeNullOrEmpty
    $VersionStrings.ProductVersion | Should -Not -BeNullOrEmpty
    $VersionStrings.FileDescription | Should -Not -BeNullOrEmpty
  }

  It 'reads layout through a caller-owned stream and restores its position' {
    $ExecutablePath = (Get-Process -Id $PID).Path
    $Stream = [IO.File]::OpenRead($ExecutablePath)
    $Stream.Position = 5
    try {
      $Layout = Get-PELayout -Stream $Stream
      $Layout.Sections.Count | Should -BeGreaterThan 0
      $Layout.Sections[0].Characteristics | Should -BeGreaterThan 0
      $Stream.Position | Should -Be 5
    } finally { $Stream.Dispose() }
  }

  It 'reads a PE layout when a large installer overlay exceeds the PEReader size limit' {
    $ExecutableBytes = [IO.File]::ReadAllBytes((Get-Process -Id $PID).Path)
    $PeOffset = [BitConverter]::ToInt32($ExecutableBytes, 0x3C)
    $OptionalHeaderOffset = $PeOffset + 24
    $DataDirectoryOffset = $OptionalHeaderOffset + $(if ([BitConverter]::ToUInt16($ExecutableBytes, $OptionalHeaderOffset) -eq 0x20B) { 112 } else { 96 })
    $CertificateEntryOffset = $DataDirectoryOffset + (4 * 8)
    $LargeCertificateOffset = [uint32]([long][int]::MaxValue + 1024)
    [BitConverter]::GetBytes($LargeCertificateOffset).CopyTo($ExecutableBytes, $CertificateEntryOffset)
    [BitConverter]::GetBytes([uint32]512).CopyTo($ExecutableBytes, $CertificateEntryOffset + 4)

    $VirtualLength = [long]$LargeCertificateOffset + 512
    $Stream = [Dumplings.Tests.VirtualLargeReadStream]::new($ExecutableBytes, $VirtualLength)
    $Stream.Position = 11
    try {
      [Dumplings.InstallerInfrastructure.PEImageReader]::GetReaderSize($Stream) | Should -Be ([int]::MaxValue)
      $Layout = Get-PELayout -Stream $Stream
      $Layout.Sections.Count | Should -BeGreaterThan 0
      $Layout.DataDirectories.Certificate.Offset | Should -Be $LargeCertificateOffset
      $Stream.Position | Should -Be 11
    } finally { $Stream.Dispose() }
  }

  It 'reuses a caller-provided PE layout while enumerating resources' {
    $ExecutablePath = (Get-Process -Id $PID).Path
    $Stream = [IO.File]::OpenRead($ExecutablePath)
    $Stream.Position = 7
    try {
      $Layout = Get-PELayout -Stream $Stream
      $Resources = @(Get-PEResourceInfo -Stream $Stream -Layout $Layout)

      $Resources.Count | Should -BeGreaterThan 0
      $Stream.Position | Should -Be 7
      [object]::ReferenceEquals($Resources[0].SourceStream, $Stream) | Should -BeTrue
    } finally { $Stream.Dispose() }
  }
}

Describe 'Shared archive helpers' {
  It 'loads filesystem path helpers from the filesystem module' {
    (Get-Command Resolve-InstallerFileSystemPath).ModuleName | Should -Be 'FileSystem'
    (Get-Command Resolve-SafeExtractionPath).ModuleName | Should -Be 'FileSystem'
    (Get-Module Binary).ExportedFunctions.Keys | Should -Not -Contain 'Resolve-InstallerFileSystemPath'
    (Get-Module Binary).ExportedFunctions.Keys | Should -Not -Contain 'Resolve-SafeExtractionPath'
  }

  It 'resolves relative paths against the PowerShell filesystem location' {
    $PowerShellRoot = Join-Path $TestDrive 'PowerShellLocation'
    $null = New-Item -Path $PowerShellRoot -ItemType Directory
    $SourcePath = Join-Path $PowerShellRoot 'source.bin'
    [IO.File]::WriteAllBytes($SourcePath, [byte[]](1, 2, 3))
    $OriginalDotNetDirectory = [Environment]::CurrentDirectory
    Push-Location $PowerShellRoot
    try {
      [Environment]::CurrentDirectory = $Script:TemporaryRoot
      Resolve-InstallerFileSystemPath -Path '.\source.bin' -PathType Leaf | Should -Be $SourcePath
      Resolve-InstallerFileSystemPath -Path '.\output' -AllowNonexistent | Should -Be (Join-Path $PowerShellRoot 'output')
    } finally {
      [Environment]::CurrentDirectory = $OriginalDotNetDirectory
      Pop-Location
    }
  }

  It 'applies deterministic extraction collision policies' {
    $OutputRoot = Join-Path $TestDrive 'Collisions'
    $null = New-Item -Path $OutputRoot -ItemType Directory
    $ExistingPath = Join-Path $OutputRoot 'payload.txt'
    [IO.File]::WriteAllText($ExistingPath, 'existing')

    { Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Error } |
      Should -Throw '*already exists*'
    (Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Skip).ShouldWrite |
      Should -BeFalse
    (Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Overwrite).Path |
      Should -Be $ExistingPath
    $Renamed = Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Rename
    $Renamed.Path | Should -Be (Join-Path $OutputRoot 'payload (1).txt')
    $Renamed.Disposition | Should -Be 'Rename'

    $Reserved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $Reserved.Add((Join-Path $OutputRoot 'new.bin'))
    (Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'new.bin' -CollisionAction Rename -ReservedPath $Reserved).Path |
      Should -Be (Join-Path $OutputRoot 'new (1).bin')
  }

  It 'prompts only when the Prompt policy encounters a collision' {
    $OutputRoot = Join-Path $TestDrive 'PromptCollision'
    $null = New-Item -Path $OutputRoot -ItemType Directory
    [IO.File]::WriteAllText((Join-Path $OutputRoot 'payload.txt'), 'existing')
    Mock Read-InstallerCollisionAction -ModuleName Binary { 'Skip' }

    $Collision = Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Prompt
    $Collision.ShouldWrite | Should -BeFalse
    $Available = Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'available.txt' -CollisionAction Prompt
    $Available.ShouldWrite | Should -BeTrue

    Should -Invoke Read-InstallerCollisionAction -ModuleName Binary -Times 1 -Exactly -ParameterFilter {
      $CollisionAction -eq 'Prompt' -and $Path -eq (Join-Path $OutputRoot 'payload.txt')
    }
  }

  It 'decodes a bounded four-stream BCJ2 payload through SharpCompress' {
    $Expected = [byte[]](1, 2, 3, 4, 5, 6)
    $Streams = [System.IO.Stream[]]@(
      [IO.MemoryStream]::new($Expected, $false),
      [IO.MemoryStream]::new([byte[]]::new(0), $false),
      [IO.MemoryStream]::new([byte[]]::new(0), $false),
      [IO.MemoryStream]::new([byte[]](0, 0, 0, 0, 0), $false)
    )
    $Decoder = New-InstallerBcj2DecoderStream -Stream $Streams -UncompressedSize $Expected.Length
    try {
      $Actual = [byte[]]::new($Expected.Length)
      $Decoder.Read($Actual, 0, $Actual.Length) | Should -Be $Expected.Length
      $Actual | Should -Be $Expected
    } finally {
      $Decoder.Dispose()
      foreach ($Stream in $Streams) { $Stream.Dispose() }
    }
  }

  It 'decodes Zstandard streams and enforces their declared output size' {
    Import-InstallerArchiveDependency
    $Expected = [Text.Encoding]::UTF8.GetBytes(('bounded-zstandard-' * 32))
    $Compressor = [ZstdSharp.Compressor]::new(3)
    try {
      $Compressed = [byte[]]::new([ZstdSharp.Compressor]::GetCompressBound($Expected.Length))
      $CompressedLength = $Compressor.Wrap($Expected, $Compressed, 0)
    } finally { $Compressor.Dispose() }

    $CompressedInput = [IO.MemoryStream]::new($Compressed, 0, $CompressedLength, $false)
    $Output = [IO.MemoryStream]::new()
    try {
      Expand-InstallerCompressedStream -Algorithm Zstd -Stream $CompressedInput -Destination $Output -MaximumBytes 4096 -CompressedSize $CompressedLength -UncompressedSize $Expected.Length | Should -Be $Expected.Length
      $Output.ToArray() | Should -Be $Expected
    } finally { $Output.Dispose(); $CompressedInput.Dispose() }

    $CompressedInput = [IO.MemoryStream]::new($Compressed, 0, $CompressedLength, $false)
    $Output = [IO.MemoryStream]::new()
    try {
      { Expand-InstallerCompressedStream -Algorithm Zstd -Stream $CompressedInput -Destination $Output -MaximumBytes 4096 -CompressedSize $CompressedLength -UncompressedSize ($Expected.Length - 1) } | Should -Throw '*exceeds its declared*'
    } finally { $Output.Dispose(); $CompressedInput.Dispose() }
  }

  It 'decodes bounded GZip members and rejects a corrupt trailer' {
    $Expected = [Text.Encoding]::UTF8.GetBytes(('astrum-gzip-payload-' * 16))
    $CompressedOutput = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.GZipStream]::new($CompressedOutput, [IO.Compression.CompressionLevel]::Optimal, $true)
    try { $Encoder.Write($Expected, 0, $Expected.Length) } finally { $Encoder.Dispose() }
    $Compressed = $CompressedOutput.ToArray()
    $CompressedOutput.Dispose()

    $CompressedInput = [IO.MemoryStream]::new($Compressed, $false)
    $Output = [IO.MemoryStream]::new()
    try {
      Expand-InstallerCompressedStream -Algorithm GZip -Stream $CompressedInput -Destination $Output -MaximumBytes 4096 -CompressedSize $Compressed.Length -UncompressedSize $Expected.Length | Should -Be $Expected.Length
      $Output.ToArray() | Should -Be $Expected
    } finally { $Output.Dispose(); $CompressedInput.Dispose() }

    $Corrupt = [byte[]]$Compressed.Clone()
    $Corrupt[$Corrupt.Length - 8] = $Corrupt[$Corrupt.Length - 8] -bxor 0xFF
    $CompressedInput = [IO.MemoryStream]::new($Corrupt, $false)
    $Output = [IO.MemoryStream]::new()
    try { { Expand-InstallerCompressedStream -Algorithm GZip -Stream $CompressedInput -Destination $Output -MaximumBytes 4096 -CompressedSize $Corrupt.Length -UncompressedSize $Expected.Length } | Should -Throw }
    finally { $Output.Dispose(); $CompressedInput.Dispose() }
  }

  It 'decodes one BZip2 member without treating trailing installer records as another member' {
    Import-InstallerArchiveDependency
    $Expected = [Text.Encoding]::UTF8.GetBytes(('deploymaster-classic-payload-' * 16))
    $CompressedOutput = [IO.MemoryStream]::new()
    $Encoder = [SharpCompress.Compressors.BZip2.BZip2Stream]::new($CompressedOutput, [SharpCompress.Compressors.CompressionMode]::Compress, $false)
    try { $Encoder.Write($Expected, 0, $Expected.Length) } finally { $Encoder.Dispose() }
    $Compressed = $CompressedOutput.ToArray() + [byte[]](0x44, 0x41, 0x54, 0x41)

    $CompressedInput = [IO.MemoryStream]::new($Compressed, $false)
    $Output = [IO.MemoryStream]::new()
    try {
      Expand-InstallerCompressedStream -Algorithm BZip2 -Stream $CompressedInput -Destination $Output -MaximumBytes 4096 | Should -Be $Expected.Length
      $Output.ToArray() | Should -Be $Expected
      $CompressedInput.CanRead | Should -BeTrue
    } finally { $Output.Dispose(); $CompressedInput.Dispose(); $CompressedOutput.Dispose() }
  }

  It 'opens and exports a bounded ZIP entry' {
    $ZipPath = Join-Path $Script:TemporaryRoot 'sample.zip'
    $SourcePath = Join-Path $Script:TemporaryRoot 'source.txt'
    [IO.File]::WriteAllText($SourcePath, 'shared archive')
    Compress-Archive -LiteralPath $SourcePath -DestinationPath $ZipPath -Force
    $Archive = Get-InstallerArchive -Path $ZipPath
    try {
      $Entry = @(Get-InstallerArchiveEntry -Archive $Archive)[0]
      $OutputPath = Resolve-SafeExtractionPath -DestinationPath (Join-Path $Script:TemporaryRoot 'out') -RelativePath $Entry.FullName
      $Result = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024
      $Result | Should -Exist
      [IO.File]::ReadAllText($Result.FullName) | Should -Be 'shared archive'

      $Renamed = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Rename
      $Renamed.Name | Should -Be 'source (1).txt'
      (Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Skip) |
        Should -BeNullOrEmpty
      { Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Error } |
        Should -Throw '*already exists*'
      (Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Overwrite).FullName |
        Should -Be $OutputPath
    } finally {
      $Archive.Dispose()
    }
  }

  It 'opens an embedded archive range without materializing it' {
    $ZipPath = Join-Path $Script:TemporaryRoot 'range-source.zip'
    $SourcePath = Join-Path $Script:TemporaryRoot 'range-source.txt'
    $EmbeddedPath = Join-Path $Script:TemporaryRoot 'embedded-range.bin'
    [IO.File]::WriteAllText($SourcePath, 'bounded range archive')
    Compress-Archive -LiteralPath $SourcePath -DestinationPath $ZipPath -Force
    $Prefix = [byte[]]::new(257)
    $ZipBytes = [IO.File]::ReadAllBytes($ZipPath)
    [IO.File]::WriteAllBytes($EmbeddedPath, $Prefix + $ZipBytes + [byte[]]::new(31))

    $Context = Open-InstallerArchiveRange -Path $EmbeddedPath -Offset $Prefix.Length -Length $ZipBytes.Length
    try {
      $Entry = @(Get-InstallerArchiveEntry -Archive $Context.Archive)[0]
      Read-InstallerArchiveEntryText -Entry $Entry -MaximumBytes 1024 | Should -Be 'bounded range archive'
    } finally {
      Close-InstallerArchiveRange -Context $Context
    }

    { Remove-Item -LiteralPath $EmbeddedPath -Force } | Should -Not -Throw
  }

  It 'extracts an empty ZIP entry after exactly consuming the output budget' {
    $Stream = [IO.MemoryStream]::new()
    $Zip = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
      $EntryStream = $Zip.CreateEntry('payload.bin').Open()
      try { $EntryStream.Write([byte[]](1, 2, 3)) } finally { $EntryStream.Dispose() }
      $null = $Zip.CreateEntry('empty.bin')
    } finally { $Zip.Dispose() }
    $Stream.Position = 0
    $Archive = Get-InstallerArchive -Stream $Stream
    try {
      $Result = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath (Join-Path $TestDrive 'exact-budget') -MaximumExpandedBytes 3
      $Result.ExpandedBytes | Should -Be 3
      $Result.Files.Count | Should -Be 2
      (Get-Item -LiteralPath (Join-Path $TestDrive 'exact-budget/empty.bin')).Length | Should -Be 0
      { Export-InstallerArchiveSelection -Archive $Archive -DestinationPath (Join-Path $TestDrive 'below-budget') -MaximumExpandedBytes 2 } | Should -Throw '*output limit*'
    } finally { $Archive.Dispose(); $Stream.Dispose() }
  }

  It 'rejects nonempty data even when an entry claims zero length and has zero budget' {
    $Stream = [IO.MemoryStream]::new([byte[]](1), $false)
    try {
      { Export-InstallerArchiveEntry -Entry ([pscustomobject]@{ Size = 0 }) -EntryStream $Stream -DestinationPath (Join-Path $TestDrive 'forged-empty.bin') -MaximumBytes 0 } | Should -Throw '*exceeds its declared 0-byte length*'
      $Stream.CanRead | Should -BeTrue
      (Get-Item -LiteralPath (Join-Path $TestDrive 'forged-empty.bin')).Length | Should -Be 0
      $Stream.Position = 0
      { Export-InstallerArchiveEntry -Entry ([pscustomobject]@{ Size = 1 }) -EntryStream $Stream -DestinationPath (Join-Path $TestDrive 'no-budget.bin') -MaximumBytes 0 } | Should -Throw '*output limit*'
      Test-Path -LiteralPath (Join-Path $TestDrive 'no-budget.bin') | Should -BeFalse
    } finally { $Stream.Dispose() }
  }

  It 'extracts a solid 7z selection without changing archive ownership: <BorrowedStream>' -ForEach @(
    @{ BorrowedStream = $true }
    @{ BorrowedStream = $false }
  ) {
    # A tiny two-file solid block plus a directory and empty file, generated
    # once with 7-Zip. Tests require only the existing SharpCompress dependency.
    $Bytes = [Convert]::FromBase64String('N3q8ryccAASxiFGwhAAAAAAAAAAhAAAAAAAAAIVDuz8BABZzb2xpZCBhbHBoYQpzb2xpZCBiZXRhCgAAAIEzB64Pz7XvEA/r6py/Nj3+dICx8gG28T6bLfJRCxeSOc2HBQVRzUzA1fbcU8h0JqYN9IqEBdbWjTAbUqIrpCdZcI4AX/8s5WDnXTY0Qg6qgwSIw7/RgJfTq2F9nsIPfV8wUv2XQAAXBhsBCWkABwsBAAEjAwEBBV0AEAAADICSCgHOe1e5AAA=')
    $Path = Join-Path $TestDrive 'solid.7z'
    [IO.File]::WriteAllBytes($Path, $Bytes)
    $Source = $null
    if ($BorrowedStream) {
      $Source = [IO.File]::OpenRead($Path)
      $Archive = Get-InstallerArchive -Stream $Source
      Mock Open-InstallerArchiveEntry -ModuleName Archive { $Entry.OpenEntryStream() }
      Mock Open-InstallerArchiveEntry -ModuleName Archive { throw 'Sequential extraction must use the reader stream.' } -ParameterFilter { $Entry.Key -eq 'first.txt' }
    } else { $Archive = Get-InstallerArchive -Path $Path }
    try {
      $Output = Join-Path $TestDrive 'solid-output'
      $Result = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $Output -MaximumExpandedBytes 23 -MaximumEntries 3
      $Result.Files.Count | Should -Be 3
      $Result.ExpandedBytes | Should -Be 23
      [IO.File]::ReadAllText((Join-Path $Output 'first.txt')) | Should -Be "solid alpha`n"
      [IO.File]::ReadAllText((Join-Path $Output 'sub/last.txt')) | Should -Be "solid beta`n"
      (Get-Item -LiteralPath (Join-Path $Output 'empty.txt')).Length | Should -Be 0
      # Reader disposal must leave the caller-owned archive reusable.
      (Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $Output -CollisionAction Skip).Files.Count | Should -Be 0
      (Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $Output -CollisionAction Rename).Files.Count | Should -Be 3
      (Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $Output -CollisionAction Overwrite).ExpandedBytes | Should -Be 23
      { Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $Output -CollisionAction Error } | Should -Throw '*already exists*'
      { Export-InstallerArchiveSelection -Archive $Archive -DestinationPath (Join-Path $TestDrive 'solid-limit') -MaximumExpandedBytes 22 } | Should -Throw '*output limit*'
      { Export-InstallerArchiveSelection -Archive $Archive -DestinationPath (Join-Path $TestDrive 'solid-count') -MaximumEntries 1 } | Should -Throw '*entry limit*'
      $Selected = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath (Join-Path $TestDrive 'solid-selected') -Name 'sub/*'
      $Selected.Files.Count | Should -Be 1
      $Selected.ExpandedBytes | Should -Be 11
    } finally { $Archive.Dispose(); if ($Source) { $Source.Dispose() } }
  }

  It 'retains caller ownership of a supplied decompressed entry stream' {
    $Stream = [IO.MemoryStream]::new([byte[]](1, 2, 3), $false)
    try {
      $File = Export-InstallerArchiveEntry -Entry ([pscustomobject]@{ Size = 3 }) -EntryStream $Stream -DestinationPath (Join-Path $TestDrive 'supplied.bin') -MaximumBytes 3
      $File.Length | Should -Be 3
      $Stream.CanRead | Should -BeTrue
      $Stream.Position = 0
      { Export-InstallerArchiveEntry -Entry ([pscustomobject]@{ Size = 4 }) -EntryStream $Stream -DestinationPath (Join-Path $TestDrive 'wrong-size.bin') -MaximumBytes 4 } | Should -Throw
      $Stream.CanRead | Should -BeTrue
      $Stream.Position = 0
      { Export-InstallerArchiveEntry -Entry ([pscustomobject]@{ Size = 2 }) -EntryStream $Stream -DestinationPath (Join-Path $TestDrive 'excess-size.bin') -MaximumBytes 3 } | Should -Throw '*exceeds its declared*'
    } finally { $Stream.Dispose() }
  }

  It 'rejects traversal and output-limit violations' {
    { Resolve-SafeExtractionPath -DestinationPath $Script:TemporaryRoot -RelativePath '..\escape.bin' } | Should -Throw
  }

  It 'derives and validates exact embedded 7z archive ranges without external tools' {
    $ArchiveBytes = [Convert]::FromBase64String('N3q8ryccAAQs8sR6JAAAAAAAAABiAAAAAAAAANg7gnEBAB/vu79EdW1wbGluZ3MgZW1iZWRkZWQgN3ogZml4dHVyZQABBAYAAQkkAAcLAQABISEBAAwgAAgKASE86hYAAAUBGQwAAAAAAAAAAAAAAAARGQBmAGkAeAB0AHUAcgBlAC4AdAB4AHQAAAAZAgAAFAoBABhQp0tLEN0BFQYBACAAAAAAAA==')
    $Prefix = [byte[]]::new(4096)
    $Suffix = [Text.Encoding]::ASCII.GetBytes('trailing-data-that-is-not-part-of-the-archive')
    $Path = Join-Path $Script:TemporaryRoot 'embedded-7z.bin'
    [IO.File]::WriteAllBytes($Path, $Prefix + $ArchiveBytes + $Suffix)

    $Ranges = @(Get-EmbeddedSevenZipArchiveRange -Path $Path -StartOffset 1024)

    $Ranges | Should -HaveCount 1
    $Ranges[0].Offset | Should -Be 4096
    $Ranges[0].Length | Should -Be $ArchiveBytes.Length
    $Ranges[0].EntryCount | Should -Be 1
  }
}
