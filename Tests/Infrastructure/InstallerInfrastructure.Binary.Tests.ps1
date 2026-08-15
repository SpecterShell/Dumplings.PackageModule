. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallerInfrastructureTestSetup.ps1')

Describe 'Find-BinaryPattern' {
  It 'finds overlapping matches and honors match limits' {
    $Bytes = [Text.Encoding]::ASCII.GetBytes('AAAAA')
    @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes('AAA'))) | Should -Be @(0, 1, 2)
    @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes('AA')) -Maximum 2) | Should -Be @(0, 1)
  }

  It 'finds a match spanning the scanner chunk boundary and supports reverse order' {
    $Path = Join-Path $Script:TemporaryRoot 'boundary.bin'
    $Bytes = [byte[]]::new(1048584)
    [Text.Encoding]::ASCII.GetBytes('PATTERN').CopyTo($Bytes, 1048573)
    [Text.Encoding]::ASCII.GetBytes('PATTERN').CopyTo($Bytes, 10)
    [IO.File]::WriteAllBytes($Path, $Bytes)
    @(Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes('PATTERN'))) | Should -Be @(10, 1048573)
    @(Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes('PATTERN')) -Reverse) | Should -Be @(1048573, 10)
    @(Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes('PATTERN')) -Reverse -Maximum 1) | Should -Be @(1048573)
  }

  It 'rejects malformed scan ranges' {
    { Find-BinaryPattern -Bytes ([byte[]](1, 2, 3)) -Pattern ([byte[]](1)) -StartOffset 4 } | Should -Throw
  }

  It 'searches caller-owned streams with alignment and restores position' {
    $Stream = [IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes('----MATCH---MATCH'))
    $Stream.Position = 3
    try {
      @(Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::ASCII.GetBytes('MATCH')) -Alignment 4) | Should -Be @(4, 12)
      $Stream.Position | Should -Be 3
    } finally { $Stream.Dispose() }
  }
}

Describe 'Bounded binary streams' {
  It 'returns byte arrays without pipeline boxing and restores random-access positions' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3, 4))
    $Source.Position = 4
    try {
      $Bytes = Read-BinaryBytes -Stream $Source -Offset 1 -Count 3
      $Bytes.GetType() | Should -Be ([byte[]])
      $Bytes | Should -Be ([byte[]](1, 2, 3))
      $Source.Position | Should -Be 4
    } finally { $Source.Dispose() }
  }

  It 'limits a substream and leaves caller-owned streams open' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3, 4, 5))
    $Range = New-BoundedReadStream -Stream $Source -Offset 2 -Length 3 -LeaveOpen
    try {
      $Output = [byte[]]::new(4)
      $Range.Read($Output, 0, $Output.Length) | Should -Be 3
      $Output[0..2] | Should -Be @(2, 3, 4)
      $Range.ReadByte() | Should -Be -1
    } finally { $Range.Dispose() }
    $Source.CanRead | Should -BeTrue
    $Source.Dispose()
  }

  It 'spills non-seekable nested content to an automatically deleted file' {
    $Raw = [byte[]]::new(32768)
    for ($Index = 0; $Index -lt $Raw.Length; $Index++) { $Raw[$Index] = $Index % 251 }
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.GZipStream]::new($Compressed, [IO.Compression.CompressionMode]::Compress, $true)
    $Encoder.Write($Raw, 0, $Raw.Length)
    $Encoder.Dispose()
    $Compressed.Position = 0
    $Decoder = [IO.Compression.GZipStream]::new($Compressed, [IO.Compression.CompressionMode]::Decompress, $true)
    $Context = New-InstallerSeekableStream -SourceStream $Decoder -MaximumBytes 65536 -MemoryThresholdBytes 1024
    $TemporaryPath = $Context.TemporaryPath
    try {
      $Context.Length | Should -Be $Raw.Length
      $TemporaryPath | Should -Not -BeNullOrEmpty
      $TemporaryPath | Should -Exist
    } finally {
      $Context.Dispose()
      $Decoder.Dispose()
      $Compressed.Dispose()
    }
    $TemporaryPath | Should -Not -Exist
  }

  It 'bounds seekable nested content from the caller current position' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3, 4))
    $Source.Position = 2
    $Context = New-InstallerSeekableStream -SourceStream $Source -MaximumBytes 3
    try {
      $Context.Length | Should -Be 3
      $Context.Stream.ReadByte() | Should -Be 2
    } finally { $Context.Dispose() }
    $Source.CanRead | Should -BeTrue
    $Source.Dispose()
  }

  It 'rejects seekable content that exceeds the spool limit' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3))
    try { { New-InstallerSeekableStream -SourceStream $Source -MaximumBytes 3 } | Should -Throw }
    finally { $Source.Dispose() }
  }

  It 'computes the standard CRC32 vector and enforces copy limits' {
    $CrcBytes = [Text.Encoding]::ASCII.GetBytes('__123456789__')
    Get-BinaryCrc32 -Bytes $CrcBytes -Offset 2 -Count 9 | Should -Be ([uint32]3421780262)
    Get-BinaryCrc32 -Bytes $CrcBytes | Should -Not -Be ([uint32]3421780262)
    { Get-BinaryCrc32 -Bytes $CrcBytes -Offset 8 -Count 6 } | Should -Throw
    $CrcSource = [IO.MemoryStream]::new([byte[]](1, 2))
    try {
      Get-BinaryCrc32 -Stream $CrcSource -SuffixBytes ([byte[]](3)) | Should -Be (Get-BinaryCrc32 -Bytes ([byte[]](1, 2, 3)))
      $CrcSource.Position | Should -Be 0
    } finally { $CrcSource.Dispose() }
    $Source = [IO.MemoryStream]::new([byte[]](1, 2, 3))
    $Destination = [IO.MemoryStream]::new()
    try { { Copy-BoundedStream -Source $Source -Destination $Destination -MaximumBytes 2 } | Should -Throw }
    finally { $Destination.Dispose(); $Source.Dispose() }
  }

  It 'copies and decodes a bounded fixed-XOR stream' {
    $Source = [IO.MemoryStream]::new([byte[]](0xC0, 0xED, 0xE4, 0xE4, 0xE7))
    $Destination = [IO.MemoryStream]::new()
    try {
      Copy-BinaryXorStream -Source $Source -Destination $Destination -Key 0x88 -ExpectedBytes 5 | Should -Be 5
      [Text.Encoding]::ASCII.GetString($Destination.ToArray()) | Should -Be 'Hello'
    } finally {
      $Destination.Dispose()
      $Source.Dispose()
    }
  }
}
