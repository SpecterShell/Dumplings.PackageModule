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
    Deep clone data without serializing away scalar types, nulls, or empty arrays
  .PARAMETER InputObject
    The object to clone
  .PARAMETER Depth
    Maximum nested data depth; cycles and deeper graphs throw rather than truncate.
  .OUTPUTS
    Detached dictionaries, object records and arrays. Immutable scalar values are
    retained; arbitrary mutable .NET resources are not cloned.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The object to clone')]
    [Alias('Value')][AllowNull()][AllowEmptyCollection()]
    $InputObject,

    [Parameter(HelpMessage = 'The depth of the object to clone')]
    [ValidateRange(0, 1024)][int]$Depth = 100
  )

  process {
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [Collections.IDictionary]) {
      if ($Depth -eq 0) { throw 'The object exceeds the copy depth limit or contains a cycle.' }
      $Copy = if ($InputObject -is [hashtable]) { $InputObject.Clone() } else { [ordered]@{} }
      $Copy.Clear()
      foreach ($Key in $InputObject.Keys) {
        if ($Copy.Contains($Key)) {
          # A case-sensitive source can contain both "Name" and "name". Preserve
          # both rather than overwriting one in PowerShell's ordered literal.
          $ExactCopy = [Collections.Specialized.OrderedDictionary]::new()
          foreach ($Entry in $Copy.GetEnumerator()) { $ExactCopy.Add($Entry.Key, $Entry.Value) }
          $Copy = $ExactCopy
        }
        $Copy[$Key] = Copy-Object -InputObject $InputObject[$Key] -Depth ($Depth - 1)
      }
      return $Copy
    }
    if ($InputObject -is [Collections.IEnumerable] -and $InputObject -isnot [string]) {
      if ($Depth -eq 0) { throw 'The object exceeds the copy depth limit or contains a cycle.' }
      $Items = [Collections.Generic.List[object]]::new()
      foreach ($Item in $InputObject) { $Items.Add((Copy-Object -InputObject $Item -Depth ($Depth - 1))) }
      return , $Items.ToArray()
    }
    # Parameter binding may wrap a string in PSObject; that wrapper is not a data
    # record. Copy its scalar value rather than its adapted Length property.
    if ($InputObject.PSObject.BaseObject -is [pscustomobject]) {
      if ($Depth -eq 0) { throw 'The object exceeds the copy depth limit or contains a cycle.' }
      $Copy = [ordered]@{}
      foreach ($Property in $InputObject.PSObject.Properties) { $Copy[$Property.Name] = Copy-Object -InputObject $Property.Value -Depth ($Depth - 1) }
      return [pscustomobject]$Copy
    }
    return $InputObject
  }
}

function Test-ObjectValueEqual {
  <#
  .SYNOPSIS
    Compare two data values structurally and case-sensitively.
  .PARAMETER Left
    The first value.
  .PARAMETER Right
    The second value.
  #>
  [OutputType([bool])]
  param ([AllowNull()]$Left, [AllowNull()]$Right)

  if ($null -eq $Left -or $null -eq $Right) {
    return $null -eq $Left -and $null -eq $Right
  }
  if ($Left -is [System.Collections.IDictionary]) {
    if ($Right -isnot [System.Collections.IDictionary] -or $Left.Count -ne $Right.Count) { return $false }
    $RightKeys = [Collections.Generic.Dictionary[object, object]]::new()
    foreach ($Key in $Right.Keys) { $RightKeys.Add($Key, $Right[$Key]) }
    foreach ($Key in $Left.Keys) {
      if (-not $RightKeys.ContainsKey($Key) -or -not (Test-ObjectValueEqual -Left $Left[$Key] -Right $RightKeys[$Key])) { return $false }
    }
    return $true
  }
  if ($Left -is [System.Collections.IEnumerable] -and $Left -isnot [string]) {
    if ($Right -isnot [System.Collections.IEnumerable] -or $Right -is [string]) { return $false }
    $LeftItems = @($Left)
    $RightItems = @($Right)
    if ($LeftItems.Count -ne $RightItems.Count) { return $false }
    for ($Index = 0; $Index -lt $LeftItems.Count; $Index++) {
      if (-not (Test-ObjectValueEqual -Left $LeftItems[$Index] -Right $RightItems[$Index])) { return $false }
    }
    return $true
  }
  return $Left -ceq $Right
}

Export-ModuleMember -Function Test-ObjectValueEqual, ConvertFrom-UnixTimeSeconds, ConvertFrom-UnixTimeMilliseconds, ConvertTo-UtcDateTime, Copy-Object, ConvertFrom-PropertyList
