#Requires -Version 7.4

# Apply default function parameters supplied by the Dumplings runner.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Property-list traversal ignores parser-created whitespace and comments.
$PropertyListIgnoredNodes = @('#whitespace', '#comment')

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

function ConvertFrom-PropertyList {
  <#
  .SYNOPSIS
    Convert a property list (plist) to hashtable
  .PARAMETER Node
    The property list as a XML node
  .EXAMPLE
    Invoke-RestMethod -Uri 'https://swcatalog.apple.com/content/catalogs/others/index-windows-1.sucatalog' | ConvertFrom-PropertyList
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The nodes that containing the text')]
    [System.Xml.XmlNode]$Node
  )

  begin {
    $Nodes = [System.Collections.Generic.List[System.Object]]::new()
  }

  process {
    if ($Node.Name -notin $PropertyListIgnoredNodes) { $Nodes.Add($Node) }
  }

  end {
    foreach ($Node in $Nodes) {
      Write-Verbose -Message "Node type is $($Node.Name)"
      switch ($Node.Name) {
        'dict' {
          $Result = [ordered]@{}
          $Key = $null
          foreach ($ChildNode in $Node.ChildNodes) {
            if ($ChildNode.Name -eq 'Key') {
              $Key = $ChildNode.'#text'
            } elseif ($ChildNode.Name -notin $PropertyListIgnoredNodes) {
              $Result[$Key] = $ChildNode | ConvertFrom-PropertyList
            }
          }
          Write-Output -InputObject $Result
        }
        'array' { @($Node.ChildNodes | ConvertFrom-PropertyList) }
        'integer' {
          $Result = $null
          if ([Int64]::TryParse($Node.'#text', [ref]$Result)) {
            Write-Output -InputObject $Result
          } elseif ([UInt64]::TryParse($Node.'#text', [ref]$Result)) {
            Write-Output -InputObject $Result
          } else {
            Write-Warning -Message "Failed to parse $($Node.'#text') as signed/unsigned integer, returning as string"
            Write-Output -InputObject $Node.'#text'
          }
        }
        'true' { $true }
        'false' { $false }
        'real' { [double]::Parse($Node.'#text') }
        'string' { if ([string]::IsNullOrEmpty($Node.'#text')) { '' } else { $Node.'#text' } }
        'date' { [datetime]::Parse($Node.'#text') }
        'data' { [System.Convert]::FromBase64String($Node.'#text') }
        'plist' { $Node.ChildNodes | ConvertFrom-PropertyList }
        '#document' { $Node.plist | ConvertFrom-PropertyList }
        default { throw "Unknown type $($Node.Name)" }
      }
    }
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

Export-ModuleMember -Function ConvertFrom-UnixTimeSeconds, ConvertFrom-UnixTimeMilliseconds, ConvertTo-UtcDateTime, Copy-Object, ConvertFrom-PropertyList
