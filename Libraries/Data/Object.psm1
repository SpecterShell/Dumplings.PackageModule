#Requires -Version 7.4

# Apply default function parameters supplied by the Dumplings runner.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

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

Export-ModuleMember -Function ConvertFrom-Xml, ConvertFrom-Ini
