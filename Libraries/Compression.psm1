# SPDX-License-Identifier: MIT
# This shared source is kept byte-identical in PackageModule and InstallerParsers.

function New-InstallerDecompressionStream {
  <#
  .SYNOPSIS
    Create a streaming decoder for a bounded installer payload
  #>
  [OutputType([System.IO.Stream])]
  param (
    [Parameter(Mandatory)][ValidateSet('Lzma', 'Lzma2', 'BZip2', 'Zlib', 'Deflate')][string]$Algorithm,
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [byte[]]$Properties,
    [long]$CompressedSize = -1,
    [long]$UncompressedSize = -1,
    [switch]$LeaveOpen
  )
  Import-InstallerArchiveDependency
  switch ($Algorithm) {
    'Lzma' {
      if (-not $Properties) { throw 'LZMA properties are required.' }
      return [SharpCompress.Compressors.LZMA.LzmaStream]::new($Properties, $Stream, $CompressedSize, $UncompressedSize)
    }
    'Lzma2' {
      if (-not $Properties) { throw 'LZMA2 properties are required.' }
      return [SharpCompress.Compressors.LZMA.LzmaStream]::new($Properties, $Stream, $CompressedSize, $UncompressedSize, $null, $true)
    }
    'BZip2' { return [SharpCompress.Compressors.BZip2.BZip2Stream]::new($Stream, [SharpCompress.Compressors.CompressionMode]::Decompress, $LeaveOpen.IsPresent) }
    'Zlib' { return [System.IO.Compression.ZLibStream]::new($Stream, [System.IO.Compression.CompressionMode]::Decompress, $LeaveOpen.IsPresent) }
    'Deflate' { return [System.IO.Compression.DeflateStream]::new($Stream, [System.IO.Compression.CompressionMode]::Decompress, $LeaveOpen.IsPresent) }
  }
}

function Expand-InstallerCompressedStream {
  <#
  .SYNOPSIS
    Decode compressed content into a destination with a hard output limit
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory)][ValidateSet('Lzma', 'Lzma2', 'BZip2', 'Zlib', 'Deflate')][string]$Algorithm,
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][System.IO.Stream]$Destination,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes,
    [byte[]]$Properties,
    [long]$CompressedSize = -1,
    [long]$UncompressedSize = -1
  )
  if ($UncompressedSize -gt $MaximumBytes) { throw "The declared decompressed size exceeds the $MaximumBytes-byte output limit." }
  $Decoder = New-InstallerDecompressionStream -Algorithm $Algorithm -Stream $Stream -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize -LeaveOpen
  try {
    $CopyArguments = @{ Source = $Decoder; Destination = $Destination; MaximumBytes = $MaximumBytes }
    if ($UncompressedSize -ge 0) { $CopyArguments.ExpectedBytes = $UncompressedSize }
    return Copy-BoundedStream @CopyArguments
  } finally {
    $Decoder.Dispose()
  }
}

function New-InstallerBcj2DecoderStream {
  <#
  .SYNOPSIS
    Create a SharpCompress BCJ2 decoder over four bounded input streams
  #>
  [OutputType([System.IO.Stream])]
  param (
    [Parameter(Mandatory)][ValidateCount(4, 4)][System.IO.Stream[]]$Stream,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$UncompressedSize
  )
  Import-InstallerArchiveDependency
  $Assembly = [SharpCompress.Archives.IArchive].Assembly
  $DecoderType = $Assembly.GetType('SharpCompress.Compressors.LZMA.Bcj2DecoderStream', $true)
  $Constructor = $DecoderType.GetConstructor(
    [Reflection.BindingFlags]'Instance,Public,NonPublic',
    $null,
    [type[]]@([System.IO.Stream[]], [byte[]], [long]),
    $null
  )
  if (-not $Constructor) { throw 'The bundled SharpCompress assembly does not expose the expected BCJ2 decoder constructor.' }
  return $Constructor.Invoke([object[]]@([System.IO.Stream[]]$Stream, [byte[]]::new(0), $UncompressedSize))
}

Export-ModuleMember -Function New-InstallerDecompressionStream, Expand-InstallerCompressedStream, New-InstallerBcj2DecoderStream
