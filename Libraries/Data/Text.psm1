#Requires -Version 7.4

# Apply default function parameters supplied by the Dumplings runner.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-BomlessUnicodeTextEncoding {
  <#
  .SYNOPSIS
    Detect likely BOM-less UTF-16 text from a bounded stream sample.
  .PARAMETER Stream
    Seekable caller-owned stream. The original position is restored before the function returns.
  .PARAMETER MaximumSampleBytes
    Maximum number of bytes inspected from the beginning of the stream.
  .OUTPUTS
    A strict UTF-16 encoding when one byte lane contains the expected NUL pattern; otherwise null.
  .NOTES
    StreamReader detects byte-order marks itself but cannot identify BOM-less UTF-16. This helper
    covers only that missing case and deliberately leaves all BOM-prefixed detection to StreamReader.
  #>
  [OutputType([System.Text.UnicodeEncoding])]
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter()]
    [ValidateRange(4, 65536)]
    [int]$MaximumSampleBytes = 4096
  )

  if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
    throw 'BOM-less Unicode detection requires a readable, seekable stream.'
  }

  $OriginalPosition = $Stream.Position
  try {
    $Stream.Position = 0
    $SampleLength = [int][Math]::Min($Stream.Length, $MaximumSampleBytes)
    if ($SampleLength -lt 4) { return $null }

    $Sample = [byte[]]::new($SampleLength)
    $Stream.ReadExactly($Sample)

    # StreamReader handles UTF-8, UTF-16, and UTF-32 BOMs. Avoid applying the
    # lane heuristic to any input that already declares its encoding.
    if (
      ($Sample[0] -eq 0xEF -and $Sample[1] -eq 0xBB -and $Sample[2] -eq 0xBF) -or
      ($Sample[0] -eq 0xFF -and $Sample[1] -eq 0xFE) -or
      ($Sample[0] -eq 0xFE -and $Sample[1] -eq 0xFF) -or
      ($Sample[0] -eq 0x00 -and $Sample[1] -eq 0x00 -and $Sample[2] -eq 0xFE -and $Sample[3] -eq 0xFF)
    ) {
      return $null
    }

    # ASCII-range text encoded as UTF-16 has NUL bytes concentrated in one
    # byte lane. Requiring both a dense lane and a sparse opposite lane avoids
    # treating ordinary text containing an occasional NUL as UTF-16.
    $EvenNulls = 0
    $OddNulls = 0
    for ($Index = 0; $Index -lt $SampleLength; $Index++) {
      if ($Sample[$Index] -eq 0) {
        if (($Index -band 1) -eq 0) { $EvenNulls++ } else { $OddNulls++ }
      }
    }

    $PairCount = [Math]::Max(1, [Math]::Floor($SampleLength / 2))
    $DenseThreshold = [Math]::Max(2, [Math]::Floor($PairCount / 4))
    $SparseThreshold = [Math]::Max(2, [Math]::Floor($PairCount / 16))
    if ($OddNulls -ge $DenseThreshold -and $EvenNulls -lt $SparseThreshold) {
      return [Text.UnicodeEncoding]::new($false, $false, $true)
    }
    if ($EvenNulls -ge $DenseThreshold -and $OddNulls -lt $SparseThreshold) {
      return [Text.UnicodeEncoding]::new($true, $false, $true)
    }
    return $null
  } finally {
    $Stream.Position = $OriginalPosition
  }
}

function Read-BoundedTextFile {
  <#
  .SYNOPSIS
    Read one bounded text file with BOM detection and a configurable legacy fallback.
  .PARAMETER Path
    File path resolved against PowerShell's filesystem location before it reaches .NET APIs.
  .PARAMETER MaximumBytes
    Maximum accepted file length in bytes.
  .PARAMETER FallbackEncoding
    Encoding used only when BOM-less input is not valid strict UTF-8.
  .OUTPUTS
    The decoded text as one string.
  #>
  [OutputType([string])]
  [CmdletBinding()]
  param (
    [Parameter(Position = 0, Mandatory)]
    [string]$Path,

    [Parameter()]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumBytes = 16MB,

    [Parameter()]
    [string]$FallbackEncoding = 'Default'
  )

  # Resolve first because .NET's process current directory may differ from
  # PowerShell's provider location in worker runspaces.
  $ResolvedPath = if (Get-Command -Name Resolve-InstallerFileSystemPath -ErrorAction SilentlyContinue) {
    Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  } else {
    (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName
  }

  $InputStream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # Validate the opened stream rather than stale directory metadata in case
    # another process replaced the file between path resolution and opening.
    if ($InputStream.Length -gt $MaximumBytes) {
      throw "The text file exceeds the configured $MaximumBytes-byte limit: $ResolvedPath"
    }
    if ($InputStream.Length -gt [int]::MaxValue) {
      throw "The text file is too large to decode as one bounded document: $ResolvedPath"
    }

    $InferredUnicodeEncoding = Get-BomlessUnicodeTextEncoding -Stream $InputStream
    $PrimaryEncoding = if ($InferredUnicodeEncoding) {
      $InferredUnicodeEncoding
    } else {
      # Strict UTF-8 allows legacy ANSI input to reach the explicit fallback
      # instead of silently replacing invalid byte sequences.
      [Text.UTF8Encoding]::new($false, $true)
    }

    $Reader = [IO.StreamReader]::new($InputStream, $PrimaryEncoding, $true, 4096, $true)
    try {
      return $Reader.ReadToEnd()
    } catch [Text.DecoderFallbackException] {
      # A structurally inferred UTF-16 document is malformed rather than ANSI;
      # preserve the strict failure instead of decoding it through a fallback.
      if ($InferredUnicodeEncoding) { throw }
    } finally {
      $Reader.Dispose()
    }

    $InputStream.Position = 0
    $LegacyEncoding = if ($FallbackEncoding -eq 'Default') {
      [Text.Encoding]::Default
    } else {
      [Text.Encoding]::GetEncoding($FallbackEncoding)
    }
    $Reader = [IO.StreamReader]::new($InputStream, $LegacyEncoding, $true, 4096, $true)
    try {
      return $Reader.ReadToEnd()
    } finally {
      $Reader.Dispose()
    }
  } finally {
    $InputStream.Dispose()
  }
}

function ConvertFrom-Base64 {
  <#
  .SYNOPSIS
    Decode a Base64 string into a UTF-8 string or a byte array
  .PARAMETER Content
    The Base64 string
  .PARAMETER Encoding
    The text encoding the Base64 string should be decoded to
  .PARAMETER AsByteStream
    Decode the Base64 string to a byte array
  #>
  [OutputType([string], ParameterSetName = 'String')]
  [OutputType([byte[]], ParameterSetName = 'Bytes')]
  [CmdletBinding(DefaultParameterSetName = 'String')]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The Base64 string')]
    [AllowEmptyString()]
    [string]$Content,

    [Parameter(ParameterSetName = 'String', HelpMessage = 'The text encoding the Base64 string should be decoded to')]
    [ArgumentCompleter({ [System.Text.Encoding]::GetEncodings() | Select-Object -ExpandProperty Name | Select-String -Pattern "^$($args[2])" -Raw | ForEach-Object -Process { $_.Contains(' ') ? "'${_}'" : $_ } })]
    [string]$Encoding = 'UTF-8',

    [Parameter(ParameterSetName = 'Bytes', HelpMessage = 'Decode the Base64 string to a byte array')]
    [switch]$AsByteStream
  )

  process {
    # Base64 payloads embedded in HTML, XML, and MIME documents are commonly
    # line-wrapped. Calculate optional padding from the encoded characters only;
    # counting line endings can append padding to an already complete payload.
    $NormalizedContent = [regex]::Replace($Content, '\s', '')
    if (-not $NormalizedContent.Contains('=')) {
      $Remainder = $NormalizedContent.Length % 4
      if ($Remainder -eq 1) {
        throw [FormatException]::new('The Base64 payload has an invalid encoded length.')
      }
      if ($Remainder -gt 1) { $NormalizedContent += '=' * (4 - $Remainder) }
    }

    $Bytes = [System.Convert]::FromBase64String($NormalizedContent)
    if ($AsByteStream) {
      $Bytes
    } else {
      [System.Text.Encoding]::GetEncoding($Encoding).GetString($Bytes)
    }
  }
}

function ConvertTo-UnescapedUri {
  <#
  .SYNOPSIS
    Unescape the URI
  .PARAMETER Uri
    The Uniform Resource Identifier (URI)
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI)')]
    [AllowEmptyString()]
    [string]$Uri
  )

  process {
    [uri]::UnescapeDataString($Uri)
  }
}

function ConvertTo-Https {
  <#
  .SYNOPSIS
    Change the scheme of the URI from HTTP to HTTPS
  .PARAMETER Uri
    The Uniform Resource Identifier (URI)
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI)')]
    [AllowEmptyString()]
    [string]$Uri
  )

  process {
    $Uri -creplace '^http://', 'https://'
  }
}

function ConvertTo-MarkdownEscapedText {
  <#
  .SYNOPSIS
    Escape the characters that could be interpreted as Markdown syntax
  .PARAMETER Content
    The string to escape the characters
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string to escape the characters')]
    [AllowEmptyString()]
    [string]$Content
  )

  process {
    $Content -replace '([_*\[\]()~`<>#+\-|{}.!\\])', '\$1'
  }
}

function Split-LineEndings {
  <#
  .SYNOPSIS
    Split string on all types of line endings
  .PARAMETER Content
    The string to split
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string to split')]
    [AllowEmptyString()]
    [string]$Content
  )

  process {
    $Content.Split([string[]]@("`r`n", "`n"), [System.StringSplitOptions]::None)
  }
}

function Convert-LineEndings {
  <#
  .SYNOPSIS
    Replace all types of line endings with the specified one
  .PARAMETER Content
    The string to convert the line endings
  .PARAMETER LineEnding
    The line ending to convert to
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The string to be converted')]
    [AllowEmptyString()]
    [string]$Content,

    [Parameter(HelpMessage = 'The line ending to convert to')]
    [ArgumentCompletions("`n", "`r`n")]
    [string]$LineEnding = "`n"
  )

  process {
    $Content.ReplaceLineEndings($LineEnding)
  }
}

function ConvertTo-OrderedList {
  <#
  .SYNOPSIS
    Prepend ordered numbers ("1. ", "2. ", ...) to each line of the strings and then concatenate the strings into one
  .PARAMETER Content
    The strings to prepend
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The strings to prepend')]
    [string[]]$Content
  )

  begin {
    $StringList = [System.Collections.Generic.List[string]]::new()
    $i = 1
  }

  process {
    foreach ($SubContent in $Content) {
      $StringList.Add(($Content -creplace '(?m)^', { "$(($i++)). " }))
    }
  }

  end {
    return $StringList -join "`n"
  }
}

function ConvertTo-UnorderedList {
  <#
  .SYNOPSIS
    Prepend "- " to each line of the strings and then concatenate the strings into one
  .PARAMETER Content
    The strings to prepend
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The strings to prepend')]
    [string[]]$Content
  )

  begin {
    $StringList = [System.Collections.Generic.List[string]]::new()
  }

  process {
    foreach ($SubContent in $Content) {
      $StringList.Add(($Content -creplace '(?m)^', '- '))
    }
  }

  end {
    return $StringList -join "`n"
  }
}

Export-ModuleMember -Function Get-BomlessUnicodeTextEncoding, Read-BoundedTextFile, ConvertFrom-Base64, ConvertTo-UnescapedUri, ConvertTo-Https, ConvertTo-MarkdownEscapedText, Split-LineEndings, Convert-LineEndings, ConvertTo-OrderedList, ConvertTo-UnorderedList
