#Requires -Version 7.4

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'PSNativeCommandUseErrorActionPreference', Justification = 'This is a built-in variable of PowerShell')]
$PSNativeCommandUseErrorActionPreference = $true

function ConvertFrom-UnixTimeSeconds {
  <#
  .SYNOPSIS
    Convert Unix time in seconds to DateTime object in UTC timezone
  .PARAMETER Seconds
    The Unix time in seconds
  #>
  [OutputType([datetime])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Unix time in seconds')]
    [long]$Seconds
  )

  process {
    [System.DateTimeOffset]::FromUnixTimeSeconds($Seconds).UtcDateTime
  }
}

function ConvertFrom-UnixTimeMilliseconds {
  <#
  .SYNOPSIS
    Convert Unix time in milliseconds to DateTime object in UTC timezone
  .PARAMETER Milliseconds
    The Unix time in milliseconds
  #>
  [OutputType([datetime])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Unix time in milliseconds')]
    [long]$Milliseconds
  )

  process {
    [System.DateTimeOffset]::FromUnixTimeMilliseconds($Milliseconds).UtcDateTime
  }
}

function ConvertTo-UtcDateTime {
  <#
  .SYNOPSIS
    Adjust DateTime object from specified timezone to UTC
  .PARAMETER DateTime
    The DateTime object
  .PARAMETER Id
    The TimeZoneInfo ID of the source timezone of the DateTime object
  #>
  [OutputType([datetime])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The DateTime object')]
    [datetime]$DateTime,

    [Parameter(Mandatory, HelpMessage = 'The TimeZoneInfo ID of the source timezone of the DateTime object')]
    [ArgumentCompleter({ [System.TimeZoneInfo]::GetSystemTimeZones() | Select-Object -ExpandProperty Id | Select-String -Pattern "^$($args[2])" -Raw | ForEach-Object -Process { $_.Contains(' ') ? "'${_}'" : $_ } })]
    [ValidateScript({ [System.TimeZoneInfo]::FindSystemTimeZoneById($_) })]
    [string]$Id
  )

  begin {
    $TimeZoneInfo = [System.TimeZoneInfo]::FindSystemTimeZoneById($Id)
  }

  process {
    [System.TimeZoneInfo]::ConvertTimeToUtc($DateTime, $TimeZoneInfo)
  }
}

function ConvertFrom-Xml {
  <#
  .SYNOPSIS
    Convert XML string to XMLDocument object
  .PARAMETER Content
    The string containing the XML content
  #>
  [OutputType([xml])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing the XML content')]
    [AllowEmptyString()]
    [string]$Content
  )

  begin {
    $StringBuilder = [System.Text.StringBuilder]::new()
  }

  process {
    $null = $StringBuilder.AppendLine($Content)
  }

  end {
    [xml]($StringBuilder.ToString() | Convert-LineEndings)
  }
}

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

function ConvertFrom-Ini {
  <#
  .SYNOPSIS
    Convert INI string into ordered hashtable
  .PARAMETER Content
    The string containing the INI content
  .PARAMETER Path
    The path to an INI file. A bounded text reader resolves the path, validates its size, and streams its content.
  .PARAMETER MaximumBytes
    The maximum accepted file size for the Path parameter set
  .PARAMETER FallbackEncoding
    The legacy encoding used when the file is neither BOM-prefixed nor valid UTF-8
  .PARAMETER DuplicateKeyAction
    How duplicate keys in the same or a repeated section are handled
  .PARAMETER CommentChars
    The characters that describe a comment
    Lines starting with the characters provided will be rendered as comments
  .PARAMETER IgnoreComments
    Remove lines determined to be comments from the resulting dictionary
  .NOTES
    These codes were modified from https://github.com/lipkau/PsIni under the MIT license

    The MIT License (MIT)

    Copyright (c) 2019 Oliver Lipkau

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
  .LINK
    https://github.com/lipkau/PsIni
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  [CmdletBinding(DefaultParameterSetName = 'Content')]
  param (
    [Parameter(ParameterSetName = 'Content', Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing the INI content')]
    [AllowEmptyString()]
    [string]$Content,

    [Parameter(ParameterSetName = 'Path', Position = 0, Mandatory, HelpMessage = 'The path to the INI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Path', HelpMessage = 'The maximum accepted file size')]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumBytes = 16MB,

    [Parameter(ParameterSetName = 'Path', HelpMessage = 'The legacy fallback text encoding name')]
    [string]$FallbackEncoding = 'Default',

    [Parameter(HelpMessage = 'How duplicate keys are handled')]
    [ValidateSet('Array', 'First', 'Last', 'Error')]
    [string]$DuplicateKeyAction = 'Array',

    [Parameter(HelpMessage = 'The characters that describe a comment')]
    [char[]]$CommentChars = @(';', '#'),

    [Parameter(HelpMessage = 'Remove lines determined to be comments from the resulting dictionary')]
    [switch]$IgnoreComments
  )

  begin {
    $SectionRegex = '^\s*\[(.+)\]\s*$'
    $KeyRegex = "^\s*(.+?)\s*=\s*(['`"]?)(.*)\2\s*$"
    $CommentRegex = "^\s*[$($CommentChars -join '')](.*)$"

    # Name of the section, in case the INI string had none
    $RootSection = '_'

    $StringBuilder = [System.Text.StringBuilder]::new()
    $CommentCount = 0
  }

  process {
    if ($PSCmdlet.ParameterSetName -eq 'Content') {
      $null = $StringBuilder.AppendLine($Content)
    }
  }

  end {
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
      $null = $StringBuilder.Append((Read-BoundedTextFile -Path $Path -MaximumBytes $MaximumBytes -FallbackEncoding $FallbackEncoding))
    }

    $Object = [ordered]@{}
    $Section = $null
    foreach ($Text in $StringBuilder.ToString() | Split-LineEndings) {
      switch -Regex ($Text) {
        $SectionRegex {
          $Section = $Matches[1]
          # Repeated sections contribute additional keys to the same case-insensitive
          # dictionary instead of discarding values parsed from the earlier occurrence.
          if (-not $Object.Contains($Section)) { $Object[$Section] = [ordered]@{} }
          $CommentCount = 0
          continue
        }
        $CommentRegex {
          if (-not $IgnoreComments) {
            if (-not $Section) {
              $Section = $RootSection
              if (-not $Object.Contains($Section)) { $Object[$Section] = [ordered]@{} }
            }
            $Key = '#Comment' + ($CommentCount++)
            $Value = $Matches[1]
            $Object[$Section][$Key] = $Value
          }
          continue
        }
        $KeyRegex {
          if (-not $Section) {
            $Section = $RootSection
            if (-not $Object.Contains($Section)) { $Object[$Section] = [ordered]@{} }
          }
          $Key = $Matches[1]
          $Value = $Matches[3].Replace('\r', "`r").Replace('\n', "`n")
          if ($Object[$Section].Contains($Key)) {
            switch ($DuplicateKeyAction) {
              'Array' {
                if ($Object[$Section][$Key] -is [array]) {
                  $Object[$Section][$Key] = @($Object[$Section][$Key]) + $Value
                } else {
                  $Object[$Section][$Key] = @($Object[$Section][$Key], $Value)
                }
              }
              'First' { }
              'Last' { $Object[$Section][$Key] = $Value }
              'Error' { throw "Duplicate INI key '$Key' in section '$Section'." }
            }
          } else {
            $Object[$Section][$Key] = $Value
          }
          continue
        }
      }
    }
    return $Object
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
  [OutputType([string])]
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
    if ($AsByteStream) {
      [System.Convert]::FromBase64String($Content)
    } else {
      # Add padding if the length of the string length is not a multiple of 4
      if ($Content.Length % 4 -ne 0) { $Content += '=' * (4 - ($Content.Length % 4)) }
      [System.Text.Encoding]::GetEncoding($Encoding).GetString([System.Convert]::FromBase64String($Content))
    }
  }
}

function ConvertTo-HtmlDecodedText {
  <#
  .SYNOPSIS
    Decode the character entities in the given text into their corresponding characters
  .PARAMETER Content
    The string with character entities
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string with character entities')]
    [AllowEmptyString()]
    [string]$Content
  )

  process {
    [System.Net.WebUtility]::HtmlDecode($Content)
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

function Split-Uri {
  <#
  .SYNOPSIS
    Split the URI
  .PARAMETER Uri
    The Uniform Resource Identifier (URI) to be splitted
  .PARAMETER Parent
    The parent part of the URI
  .PARAMETER LeftPart
    The left part of the URI
  .PARAMETER Components
    The component of the URI
  .PARAMETER Format
    Control how special characters are escaped
  #>
  [OutputType([string])]
  [CmdletBinding(DefaultParameterSetName = 'ParentSet')]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'Result', Justification = 'False positive')]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI) to be splitted')]
    [uri]$Uri,

    [Parameter(ParameterSetName = 'ParentSet', HelpMessage = 'The parent part of the URI')]
    [switch]$Parent,

    [Parameter(ParameterSetName = 'LeftPartSet', HelpMessage = 'The left part of the URI')]
    [System.UriPartial]$LeftPart = [System.UriPartial]::Path,

    [Parameter(ParameterSetName = 'ComponentSet', HelpMessage = 'The component of the URI')]
    [System.UriComponents[]]$Components,

    [Parameter(ParameterSetName = 'ComponentSet', HelpMessage = 'Control how special characters are escaped')]
    [System.UriFormat]$Format = [System.UriFormat]::UriEscaped
  )

  process {
    switch ($PSCmdlet.ParameterSetName) {
      'ParentSet' {
        return [uri]::new($Uri, '.').OriginalString
      }
      'LeftPartSet' {
        return $Uri.GetLeftPart($LeftPart)
      }
      'ComponentSet' {
        $Components = $Components | ForEach-Object -Begin { $Result = $null } -Process { $Result = $_ -bor $Result } -End { $Result }
        return $Uri.GetComponents($Components, $Format)
      }
      default {
        throw 'Invalid parameter set'
      }
    }
  }
}

function Join-Uri {
  <#
  .SYNOPSIS
    Join the URIs
  .PARAMETER Uri
    The main URI to which the child URI is appended
  .PARAMETER ChildUri
    The elements to be applied to the main URI
  .PARAMETER AdditionalChildUri
    Additional elements to be applied to the main URI
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The main URI to which the child URI is appended')]
    [uri[]]$Uri,

    [Parameter(Position = 1, Mandatory, HelpMessage = 'The elements to be applied to the main URI')]
    [string[]]$ChildUri,

    [Parameter(Position = 2, ValueFromRemainingArguments, HelpMessage = 'Additional elements to be applied to the main URI')]
    [string[]]$AdditionalChildUri
  )

  process {
    foreach ($SubUri in $Uri) {
      foreach ($SubChildUri in $ChildUri) {
        $SubUri = [uri]::new($SubUri, $SubChildUri, $true)
      }
      foreach ($SubAdditionalChildUri in $AdditionalChildUri) {
        $SubUri = [uri]::new($SubUri, $SubAdditionalChildUri, $true)
      }
      Write-Output -InputObject $SubUri.AbsoluteUri
    }
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

function New-TempFile {
  <#
  .SYNOPSIS
    Create a new temporary file in DumplingsCache or system temp folder
  .OUTPUTS
    The path to the new temporary file
  #>
  [OutputType([string])]

  $Parent = (Test-Path -Path Variable:\DumplingsCache) -and (Test-Path -Path $Global:DumplingsCache) ? $Global:DumplingsCache : [System.IO.Path]::GetTempPath()
  $Path = (New-Item -Path $Parent -Name (New-Guid).Guid -ItemType File -Force).FullName
  return $Path
}

function New-TempFolder {
  <#
  .SYNOPSIS
    Create a new temporary folder in DumplingsCache or system temp folder
  .OUTPUTS
    The path to the new temporary folder
  #>
  [OutputType([string])]

  $Parent = (Test-Path -Path Variable:\DumplingsCache) -and (Test-Path -Path $Global:DumplingsCache) ? $Global:DumplingsCache : [System.IO.Path]::GetTempPath()
  $Path = (New-Item -Path $Parent -Name (New-Guid).Guid -ItemType Directory -Force).FullName
  return $Path
}

function Get-TempFile {
  <#
  .SYNOPSIS
    Download the file from the given URL to a temporary file and return its path
  .NOTES
    All the parameters except '-OutFile' will be passed to Invoke-WebRequest
  .OUTPUTS
    The path to the new temporary file
  #>
  [OutputType([string])]

  $FilePath = New-TempFile
  Invoke-WebRequest -OutFile $FilePath @args
  return $FilePath
}

function Expand-TempArchive {
  <#
  .SYNOPSIS
    Extract files from the given ZIP archive to a temporary folder and return the path of the destination folder
  .PARAMETER Path
    The path of the ZIP archive to be extracted
  .PARAMETER Name
    Optional wildcard selecting archive paths or file names. All entries are extracted when omitted.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple entries resolve to the same path.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate number of bytes written from the archive.
  .OUTPUTS
    The path of the destination folder
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the ZIP archive')]
    [string]$Path,

    [Alias('RelativeFilePath')]
    [Parameter(HelpMessage = 'The wildcard selecting archive entries to extract')]
    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = 2147483648
  )

  process {
    $TempFolderPath = New-TempFolder
    try {
      $ArchivePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      $Archive = Get-InstallerArchive -Path $ArchivePath
      try {
        # Route ZIP extraction through the shared bounded archive layer so large
        # archives are streamed and every selected path receives the same
        # traversal, collision, and aggregate-output handling as installers.
        $Result = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $TempFolderPath -Name $Name `
          -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
        if ($Name -ne '*' -and $Result.EntryCount -eq 0) {
          throw "The ZIP archive does not contain an entry matching: $Name"
        }
      } finally {
        $Archive.Dispose()
      }
      return $TempFolderPath
    } catch {
      Remove-Item -LiteralPath $TempFolderPath -Recurse -Force -ErrorAction SilentlyContinue
      throw
    }
  }
}

function Get-RedirectedUrl {
  <#
  .SYNOPSIS
    Get the redirected URI for the given URI
  #>
  [OutputType([string])]
  param ()

  (Invoke-WebRequest -Method Head @args).BaseResponse.RequestMessage.RequestUri.AbsoluteUri
}

function Get-WebResponseHeader {
  <#
  .SYNOPSIS
    Get response headers without buffering the response body
  .PARAMETER Uri
    The Uniform Resource Identifier (URI)
  .PARAMETER Method
    The HTTP method for the web request
  .PARAMETER Headers
    The header hashtable for the web request
  .PARAMETER UserAgent
    The user agent string for the web request
  .PARAMETER ConnectionTimeoutSeconds
    The timeout in seconds for the web request
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI)')]
    [string]$Uri,

    [Parameter(HelpMessage = 'The HTTP method for the web request')]
    [ValidateSet('GET', 'HEAD')]
    [System.Net.Http.HttpMethod]$Method = [System.Net.Http.HttpMethod]::Get,

    [Parameter(HelpMessage = 'The header hashtable for the web request')]
    [System.Collections.IDictionary]$Headers,

    [Parameter(HelpMessage = 'The user agent string for the web request')]
    [string]$UserAgent,

    [Parameter(HelpMessage = 'The timeout in seconds for the web request')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$ConnectionTimeoutSeconds
  )

  process {
    $HttpClientHandler = [System.Net.Http.HttpClientHandler]@{ AllowAutoRedirect = $true }
    $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)
    $HttpClient.Timeout = $ConnectionTimeoutSeconds ? [timespan]::FromSeconds($ConnectionTimeoutSeconds) : [System.Threading.Timeout]::InfiniteTimeSpan
    $HttpRequest = [System.Net.Http.HttpRequestMessage]::new($Method, $Uri)
    $HttpResponse = $null

    try {
      if ($Headers) { $Headers.GetEnumerator().ForEach({ $null = $HttpRequest.Headers.TryAddWithoutValidation($_.Key, $_.Value) }) }
      if ($UserAgent) { $HttpRequest.Headers.Add('User-Agent', $UserAgent) }

      $HttpResponse = $HttpClient.Send($HttpRequest, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
      $null = $HttpResponse.EnsureSuccessStatusCode()

      $ResponseHeaders = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Header in $HttpResponse.Headers) { $ResponseHeaders[$Header.Key] = @($Header.Value) }
      foreach ($Header in $HttpResponse.Content.Headers) { $ResponseHeaders[$Header.Key] = @($Header.Value) }

      [pscustomobject]@{
        StatusCode   = [int]($HttpResponse.StatusCode)
        ReasonPhrase = $HttpResponse.ReasonPhrase
        RequestUri   = $HttpResponse.RequestMessage.RequestUri.AbsoluteUri
        Headers      = $ResponseHeaders
      }
    } finally {
      if ($HttpResponse) { $HttpResponse.Dispose() }
      $HttpRequest.Dispose()
      $HttpClient.Dispose()
      $HttpClientHandler.Dispose()
    }
  }
}

function Get-RedirectedUrls {
  <#
  .SYNOPSIS
    Get the redirected URIs for the given URI
  .PARAMETER Uri
    The Uniform Resource Identifier (URI)
  .PARAMETER Method
    The HTTP method for the web request
  .PARAMETER Headers
    The header hashtable for the web request
  .PARAMETER UserAgent
    The user agent string for the web request
  .PARAMETER ConnectionTimeoutSeconds
    The timeout in seconds for the web request
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI)')]
    [string]$Uri,

    [Parameter(HelpMessage = 'The HTTP method for the web request')]
    [ValidateSet('GET', 'HEAD')]
    [System.Net.Http.HttpMethod]$Method = [System.Net.Http.HttpMethod]::Head,

    [Parameter(HelpMessage = 'The header hashtable for the web request')]
    [System.Collections.IDictionary]$Headers,

    [Parameter(HelpMessage = 'The user agent string for the web request')]
    [string]$UserAgent,

    [Parameter(HelpMessage = 'The timeout in seconds for the web request')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$ConnectionTimeoutSeconds
  )

  begin {
    $HttpClientHandler = [System.Net.Http.HttpClientHandler]@{ AllowAutoRedirect = $false }
    $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)
    $HttpClient.Timeout = $ConnectionTimeoutSeconds ? [timespan]::FromSeconds($ConnectionTimeoutSeconds) : [System.Threading.Timeout]::InfiniteTimeSpan
  }

  process {
    $ShouldContinue = $true
    $HasRedirected = $false
    do {
      $HttpRequest = [System.Net.Http.HttpRequestMessage]::new($Method, $Uri)
      if ($Headers) { $Headers.GetEnumerator().ForEach({ $null = $HttpRequest.Headers.TryAddWithoutValidation($_.Key, $_.Value) }) }
      if ($UserAgent) { $HttpRequest.Headers.Add('User-Agent', $UserAgent) }

      $HttpResponse = $HttpClient.Send($HttpRequest, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)

      if ($HttpResponse.Headers.Contains('Location') -and $HttpResponse.Headers.Location.AbsoluteUri -ne $Uri) {
        $Uri = $HttpResponse.Headers.Location.AbsoluteUri
        $HasRedirected = $true
        Write-Output -InputObject $Uri
      } else {
        $ShouldContinue = $false
        # Usually, the original URI is not returned for intuition
        # But if no redirection happens, the original URI will be returned
        if (-not $HasRedirected) { Write-Output -InputObject $Uri }
      }

      $HttpResponse.Dispose()
      $HttpRequest.Dispose()
    } while ($ShouldContinue)
  }

  end {
    $HttpClient.Dispose()
  }
}

function Get-RedirectedUrl1st {
  <#
  .SYNOPSIS
    Get the first redirected URI for the given URI
  #>
  [OutputType([string])]
  param ()

  Get-RedirectedUrls @args | Select-Object -First 1
}

function Get-EmbeddedJson {
  <#
  .SYNOPSIS
    Extract embedded JSON from string. Useful for JSONP content
  .PARAMETER InputObject
    The string containing the JSON
  .PARAMETER StartsFrom
    The string indicating where the JSON starts after
  .LINK
    https://stackoverflow.com/questions/48470971/how-to-deserialize-a-jsonp-response-preferably-with-jsontextreader-and-not-a-st
  .LINK
    https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Utility/commands/utility/WebCmdlet/JsonObject.cs
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing the JSON')]
    [ValidateNotNullOrEmpty()]
    [string]$Content,

    [Parameter(HelpMessage = 'The string indicating where the JSON starts after')]
    [string]$StartsFrom
  )

  process {
    [Newtonsoft.Json.JsonConvert]::DeserializeObject(
      $Content.Substring($Content.IndexOf($StartsFrom) + $StartsFrom.Length),
      [Newtonsoft.Json.JsonSerializerSettings]@{
        TypeNameHandling         = [Newtonsoft.Json.TypeNameHandling]::None
        MetadataPropertyHandling = [Newtonsoft.Json.MetadataPropertyHandling]::Ignore
        CheckAdditionalContent   = $false
      }
    ).ToString()
  }
}

function Get-EmbeddedLinks {
  <#
  .SYNOPSIS
    Extract embedded <a>links</a> from string
  .PARAMETER InputObject
    The string containing the links
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing the links')]
    [ValidateNotNullOrEmpty()]
    [string]$Content
  )

  begin {
    $LinkRegex = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject].GetNestedType('HtmlParser', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static).GetField('LinkRegex', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static).GetValue($null)
    $CreateHtmlObject = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject].GetMethod('CreateHtmlObject', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static)
  }

  process {
    foreach ($Match in $LinkRegex.Matches($Content)) {
      Write-Output -InputObject $CreateHtmlObject.Invoke($null, @($Match.Value, 'A'))
    }
  }
}

function Read-ResponseContent {
  <#
  .SYNOPSIS
    Obtain garble-free content from the stream
  .PARAMETER Response
    The stream to read (e.g. The raw content stream from Invoke-WebRequest)
  .PARAMETER Encoding
    The content encoding
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The stream to read (e.g. The raw content stream from Invoke-WebRequest)')]
    [System.IO.Stream]$RawContentStream,

    [Parameter(HelpMessage = 'The content encoding')]
    [ArgumentCompleter({ [System.Text.Encoding]::GetEncodings() | Select-Object -ExpandProperty Name | Select-String -Pattern "^$($args[2])" -Raw | ForEach-Object -Process { $_.Contains(' ') ? "'${_}'" : $_ } })]
    [string]$Encoding
  )

  process {
    # The stream of the response content passed to function may be closed.
    # Force open the stream by setting the pointer to the beginning
    $RawContentStream.Position = 0
    if ($Encoding) {
      return [System.IO.StreamReader]::new($RawContentStream, [System.Text.Encoding]::GetEncoding($Encoding)).ReadToEnd()
    } else {
      return [System.IO.StreamReader]::new($RawContentStream).ReadToEnd()
    }
  }
}

function Read-ProductVersionFromExe {
  <#
  .SYNOPSIS
    Read the product version of the EXE file
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersion.Trim()
  }
}

function Read-ProductVersionRawFromExe {
  <#
  .SYNOPSIS
    Read the raw product version of the EXE file
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([version])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersionRaw
  }
}

function Read-FileVersionFromExe {
  <#
  .SYNOPSIS
    Read the file version property of the EXE file
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion.Trim()
  }
}

function Read-FileVersionRawFromExe {
  <#
  .SYNOPSIS
    Read the raw file version of the EXE file
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([version])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersionRaw
  }
}

function Copy-Object {
  <#
  .SYNOPSIS
    Deep clone an object
  .PARAMETER InputObject
    The object to clone
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The object to clone')]
    $InputObject,

    [Parameter(HelpMessage = 'The depth of the object to clone')]
    [int]$Depth = 10
  )

  process {
    $InputObject | ConvertTo-Json -Depth $Depth -Compress | ConvertFrom-Json -AsHashtable
  }
}

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'DumplingsDefaultUserAgent', Justification = 'This variable will be exported')]
$DumplingsDefaultUserAgent = [Microsoft.PowerShell.Commands.PSUserAgent].GetProperty('UserAgent', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static).GetValue($null)
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'DumplingsBrowserUserAgent', Justification = 'This variable will be exported')]
$DumplingsBrowserUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0'
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'DumplingsInternetExplorerUserAgent', Justification = 'This variable will be exported')]
$DumplingsInternetExplorerUserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'

Export-ModuleMember -Function * -Variable 'DumplingsDefaultUserAgent', 'DumplingsBrowserUserAgent', 'DumplingsInternetExplorerUserAgent'
