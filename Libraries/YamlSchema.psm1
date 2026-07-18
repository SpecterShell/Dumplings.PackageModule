# Generic JSON Schema processing for PowerShell objects serialized as YAML.
# The module intentionally performs no YAML parsing and never accesses the
# network unless the caller explicitly supplies -AllowNetworkReference.

Set-StrictMode -Version 3

function New-YamlSchemaDiagnostic {
  <#
  .SYNOPSIS
    Create one structured schema validation diagnostic.
  .PARAMETER Keyword
    The JSON Schema keyword that produced the diagnostic.
  .PARAMETER Message
    A human-readable description of the validation failure.
  .PARAMETER Field
    The object field associated with the failure, when applicable.
  .PARAMETER Value
    The invalid value.
  .PARAMETER ObjectPath
    The JSONPath-like location of the value in the input object.
  .PARAMETER SchemaPath
    The JSON Pointer location of the applicable schema node.
  .PARAMETER Reason
    A stable reason that further classifies the keyword failure.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Keyword,
    [Parameter(Mandatory)][string]$Message,
    [string]$Field,
    $Value,
    [string]$ObjectPath = '$',
    [string]$SchemaPath = '#',
    [string]$Reason
  )

  return [pscustomobject]@{
    PSTypeName = 'Dumplings.YamlSchema.Diagnostic'
    Keyword    = $Keyword
    Reason     = $Reason
    Message    = $Message
    Field      = $Field
    Value      = $Value
    ObjectPath = $ObjectPath
    SchemaPath = $SchemaPath
  }
}

function Copy-YamlSchemaObject {
  <#
  .SYNOPSIS
    Deep-copy dictionaries and arrays without changing scalar values.
  .PARAMETER InputObject
    The value to copy.
  #>
  param ([AllowNull()]$InputObject)

  if ($InputObject -is [System.Collections.IDictionary]) {
    $Result = [ordered]@{}
    foreach ($Key in $InputObject.Keys) {
      $Result[$Key] = Copy-YamlSchemaObject -InputObject $InputObject[$Key]
    }
    return $Result
  }
  if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    return , @($InputObject | ForEach-Object { Copy-YamlSchemaObject -InputObject $_ })
  }
  return $InputObject
}

function Test-YamlSchemaValueEqual {
  <#
  .SYNOPSIS
    Compare two schema values using JSON structural equality.
  .PARAMETER Left
    The left value.
  .PARAMETER Right
    The right value.
  #>
  [OutputType([bool])]
  param ([AllowNull()]$Left, [AllowNull()]$Right)

  if ($null -eq $Left -or $null -eq $Right) {
    return $null -eq $Left -and $null -eq $Right
  }
  if ($Left -is [System.Collections.IDictionary]) {
    if ($Right -isnot [System.Collections.IDictionary] -or $Left.Count -ne $Right.Count) { return $false }
    foreach ($Key in $Left.Keys) {
      $RightKey = $Right.Keys | Where-Object { $_ -ceq $Key } | Select-Object -First 1
      if ($null -eq $RightKey -or -not (Test-YamlSchemaValueEqual -Left $Left[$Key] -Right $Right[$RightKey])) { return $false }
    }
    return $true
  }
  if ($Left -is [System.Collections.IEnumerable] -and $Left -isnot [string]) {
    if ($Right -isnot [System.Collections.IEnumerable] -or $Right -is [string]) { return $false }
    $LeftItems = @($Left)
    $RightItems = @($Right)
    if ($LeftItems.Count -ne $RightItems.Count) { return $false }
    for ($Index = 0; $Index -lt $LeftItems.Count; $Index++) {
      if (-not (Test-YamlSchemaValueEqual -Left $LeftItems[$Index] -Right $RightItems[$Index])) { return $false }
    }
    return $true
  }
  return $Left -ceq $Right
}

function Get-YamlSchemaValue {
  <#
  .SYNOPSIS
    Resolve a JSON Schema reference against a root schema.
  .DESCRIPTION
    Supports local JSON Pointers and relative JSON files. Absolute network
    references are rejected unless AllowNetworkReference is explicitly set.
  .PARAMETER InputObject
    The root schema used for local references.
  .PARAMETER Ref
    The reference to resolve.
  .PARAMETER Path
    The directory used to resolve relative schema files.
  .PARAMETER AllowNetworkReference
    Permit downloading an absolute HTTP or HTTPS schema reference.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]$InputObject,
    [Parameter(Position = 1, Mandatory)][ValidateNotNullOrWhiteSpace()][string]$Ref,
    [Parameter(Position = 2)][string]$Path,
    [switch]$AllowNetworkReference
  )

  process {
    $ReferenceParts = $Ref.Split('#', 2)
    $ReferenceSource = $ReferenceParts[0]
    $ReferencePath = $ReferenceParts.Count -gt 1 ? $ReferenceParts[1] : ''
    $ReferenceSchema = $InputObject

    # External references are resolved only from an explicit local root or an
    # explicitly authorized network source, keeping normal validation offline.
    if (-not [string]::IsNullOrWhiteSpace($ReferenceSource)) {
      $ReferenceUri = $null
      if ([uri]::TryCreate($ReferenceSource, [UriKind]::Absolute, [ref]$ReferenceUri) -and
        $ReferenceUri.Scheme -cin @('http', 'https')) {
        if (-not $AllowNetworkReference) {
          throw "Network schema reference '${ReferenceSource}' is disabled"
        }
        $ReferenceSchema = Invoke-RestMethod -Uri $ReferenceUri -Method Get
        if ($ReferenceSchema -isnot [System.Collections.IDictionary]) {
          $ReferenceSchema = $ReferenceSchema | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
        }
      } elseif ($Path) {
        $ReferenceFile = Join-Path -Path $Path -ChildPath $ReferenceSource
        if (-not (Test-Path -LiteralPath $ReferenceFile -PathType Leaf)) {
          throw "Schema reference file '${ReferenceSource}' does not exist under '${Path}'"
        }
        $ReferenceSchema = Get-Content -LiteralPath $ReferenceFile -Raw | ConvertFrom-Json -AsHashtable
      } else {
        throw "Schema reference '${ReferenceSource}' requires a schema root path"
      }
    }

    if ([string]::IsNullOrEmpty($ReferencePath)) { return $ReferenceSchema }
    if (-not $ReferencePath.StartsWith('/')) {
      throw "Schema reference path '${ReferencePath}' is not a JSON Pointer"
    }

    # RFC 6901 escapes '/' as '~1' and '~' as '~0'. Array indices are also
    # accepted so references can target definitions contained in sequences.
    $Current = $ReferenceSchema
    foreach ($RawSegment in $ReferencePath.Substring(1).Split('/')) {
      $Segment = $RawSegment.Replace('~1', '/').Replace('~0', '~')
      if ($Current -is [System.Collections.IDictionary] -and $Current.Contains($Segment)) {
        $Current = $Current[$Segment]
      } elseif ($Current -is [System.Collections.IList] -and $Segment -match '^\d+$' -and [int]$Segment -lt $Current.Count) {
        $Current = $Current[[int]$Segment]
      } else {
        throw "Schema reference path '${ReferencePath}' does not exist"
      }
    }
    return $Current
  }
}

function Expand-YamlSchemaNode {
  <#
  .SYNOPSIS
    Recursively expand references in one schema node.
  .PARAMETER InputObject
    The node to expand.
  .PARAMETER RootObject
    The root schema used to resolve references.
  .PARAMETER Path
    The directory used for relative references.
  .PARAMETER ReferenceStack
    Active references used to detect direct cycles.
  .PARAMETER Depth
    Current recursion depth.
  .PARAMETER MaximumDepth
    Maximum permitted recursion depth.
  #>
  param (
    [AllowNull()]$InputObject,
    [Parameter(Mandatory)]$RootObject,
    [string]$Path,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$ReferenceStack,
    [int]$Depth,
    [int]$MaximumDepth
  )

  if ($Depth -gt $MaximumDepth) { throw "Schema expansion exceeded the maximum depth of ${MaximumDepth}" }
  if ($InputObject -is [System.Collections.IDictionary]) {
    if ($InputObject.Contains('$ref')) {
      $Reference = [string]$InputObject['$ref']
      if (-not $ReferenceStack.Add($Reference)) { throw "Cyclic schema reference detected at '${Reference}'" }
      try {
        return Expand-YamlSchemaNode -InputObject (Get-YamlSchemaValue -InputObject $RootObject -Ref $Reference -Path $Path) -RootObject $RootObject -Path $Path -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth
      } finally {
        $null = $ReferenceStack.Remove($Reference)
      }
    }

    $Result = [ordered]@{}
    foreach ($Key in $InputObject.Keys) {
      $Result[$Key] = Expand-YamlSchemaNode -InputObject $InputObject[$Key] -RootObject $RootObject -Path $Path -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth
    }
    return $Result
  }
  if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    return , @($InputObject | ForEach-Object {
        Expand-YamlSchemaNode -InputObject $_ -RootObject $RootObject -Path $Path -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth
      })
  }
  return $InputObject
}

function Expand-YamlSchema {
  <#
  .SYNOPSIS
    Return a deep-copied schema with all supported references expanded.
  .PARAMETER InputObject
    The schema to expand.
  .PARAMETER Clone
    Retained for call-site readability; expansion always returns a new object.
  .PARAMETER Path
    The directory used for relative schema references.
  .PARAMETER MaximumDepth
    Maximum schema recursion depth.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]$InputObject,
    [switch]$Clone,
    [string]$Path,
    [ValidateRange(1, 1024)][int]$MaximumDepth = 128
  )

  process {
    $Stack = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    return Expand-YamlSchemaNode -InputObject $InputObject -RootObject $InputObject -Path $Path -ReferenceStack $Stack -Depth 0 -MaximumDepth $MaximumDepth
  }
}

function Invoke-YamlSchemaNodeValidation {
  <#
  .SYNOPSIS
    Validate one input value against one schema node.
  .PARAMETER InputObject
    The value being validated.
  .PARAMETER Schema
    The current schema node.
  .PARAMETER RootSchema
    The root schema used for references.
  .PARAMETER ObjectPath
    Current path in the input object.
  .PARAMETER SchemaPath
    Current path in the schema.
  .PARAMETER ValidatePropertyNames
    Report unknown and incorrectly cased properties.
  .PARAMETER ReferenceStack
    Active reference/object-path pairs used for cycle detection.
  .PARAMETER Depth
    Current recursion depth.
  .PARAMETER MaximumDepth
    Maximum validation recursion depth.
  #>
  param (
    [AllowNull()]$InputObject,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Schema,
    [Parameter(Mandatory)][System.Collections.IDictionary]$RootSchema,
    [string]$ObjectPath,
    [string]$SchemaPath,
    [switch]$ValidatePropertyNames,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$ReferenceStack,
    [int]$Depth,
    [int]$MaximumDepth
  )

  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  if ($Depth -gt $MaximumDepth) {
    $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword '$ref' -Reason MaximumDepth -Message "Schema validation exceeded the maximum depth of ${MaximumDepth}." -ObjectPath $ObjectPath -SchemaPath $SchemaPath))
    return $Diagnostics.ToArray()
  }

  # Resolve references lazily so recursive data schemas can advance through the
  # input object while a direct reference cycle at one object path is rejected.
  if ($Schema.Contains('$ref')) {
    $Reference = [string]$Schema['$ref']
    $ReferenceKey = "${Reference}|${ObjectPath}"
    if (-not $ReferenceStack.Add($ReferenceKey)) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword '$ref' -Reason Cycle -Message "Cyclic schema reference detected at '${Reference}'." -ObjectPath $ObjectPath -SchemaPath $SchemaPath))
      return $Diagnostics.ToArray()
    }
    try {
      $Resolved = Get-YamlSchemaValue -InputObject $RootSchema -Ref $Reference
      return Invoke-YamlSchemaNodeValidation -InputObject $InputObject -Schema $Resolved -RootSchema $RootSchema -ObjectPath $ObjectPath -SchemaPath $Reference -ValidatePropertyNames:$ValidatePropertyNames -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth
    } catch {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword '$ref' -Reason InvalidReference -Message $_.Exception.Message -ObjectPath $ObjectPath -SchemaPath $SchemaPath))
      return $Diagnostics.ToArray()
    } finally {
      $null = $ReferenceStack.Remove($ReferenceKey)
    }
  }

  # oneOf and not are evaluated before the base node so their constraints are
  # enforced in addition to any sibling keywords on the schema node.
  if ($Schema.Contains('oneOf')) {
    $AlternativeMatches = 0
    foreach ($Alternative in @($Schema['oneOf'])) {
      $AlternativeDiagnostics = @(Invoke-YamlSchemaNodeValidation -InputObject $InputObject -Schema $Alternative -RootSchema $RootSchema -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/oneOf" -ValidatePropertyNames:$ValidatePropertyNames -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth)
      if ($AlternativeDiagnostics.Count -eq 0) { $AlternativeMatches++ }
    }
    if ($AlternativeMatches -ne 1) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword oneOf -Reason MatchCount -Message "Value must match exactly one schema alternative; matched ${AlternativeMatches}." -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/oneOf"))
    }
  }
  if ($Schema.Contains('not')) {
    $NotDiagnostics = @(Invoke-YamlSchemaNodeValidation -InputObject $InputObject -Schema $Schema['not'] -RootSchema $RootSchema -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/not" -ValidatePropertyNames:$ValidatePropertyNames -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth)
    if ($NotDiagnostics.Count -eq 0) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword not -Reason ProhibitedMatch -Message 'Value matches a prohibited schema.' -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/not"))
    }
  }

  # Determine the JSON type represented by the PowerShell value. Integer is a
  # valid number, while strings are deliberately never coerced here.
  $AllowedTypes = @($Schema.Contains('type') ? $Schema['type'] : @())
  if ($AllowedTypes.Count -gt 0) {
    $ActualType = if ($null -eq $InputObject) { 'null' }
    elseif ($InputObject -is [System.Collections.IDictionary]) { 'object' }
    elseif ($InputObject -is [bool]) { 'boolean' }
    elseif ($InputObject -is [byte] -or $InputObject -is [sbyte] -or $InputObject -is [short] -or $InputObject -is [ushort] -or $InputObject -is [int] -or $InputObject -is [uint] -or $InputObject -is [long] -or $InputObject -is [ulong]) { 'integer' }
    elseif ($InputObject -is [float] -or $InputObject -is [double] -or $InputObject -is [decimal]) { 'number' }
    elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) { 'array' }
    elseif ($InputObject -is [string]) { 'string' }
    else { $InputObject.GetType().Name }
    if ($ActualType -cnotin $AllowedTypes -and -not ($ActualType -ceq 'integer' -and 'number' -cin $AllowedTypes)) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword type -Reason TypeMismatch -Message "Expected type '$($AllowedTypes -join '|')', found '${ActualType}'." -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/type"))
      return $Diagnostics.ToArray()
    }
  }
  if ($null -eq $InputObject) { return $Diagnostics.ToArray() }

  if ($Schema.Contains('enum') -and -not @($Schema['enum']).Where({ Test-YamlSchemaValueEqual -Left $InputObject -Right $_ }, 'First')) {
    $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword enum -Reason NotAllowed -Message 'Value is not in the allowed enumeration.' -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/enum"))
  }
  if ($Schema.Contains('const') -and -not (Test-YamlSchemaValueEqual -Left $InputObject -Right $Schema['const'])) {
    $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword const -Reason NotEqual -Message "Value must equal '$($Schema['const'])'." -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/const"))
  }

  if ($InputObject -is [System.Collections.IDictionary]) {
    foreach ($RequiredProperty in @($Schema.Contains('required') ? $Schema['required'] : @())) {
      if (-not $InputObject.Contains($RequiredProperty)) {
        $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword required -Reason MissingProperty -Message "Required property '${RequiredProperty}' is missing." -Field $RequiredProperty -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/required"))
      }
    }
    if ($Schema.Contains('properties')) {
      foreach ($Key in $InputObject.Keys) {
        # OrderedDictionary lookups can be case-insensitive, so compare key
        # text ordinally before deciding whether casing is valid.
        $ExactKey = $Schema['properties'].Keys | Where-Object { $_ -ceq $Key } | Select-Object -First 1
        if ($null -ne $ExactKey) {
          $Diagnostics.AddRange(@(Invoke-YamlSchemaNodeValidation -InputObject $InputObject[$Key] -Schema $Schema['properties'][$ExactKey] -RootSchema $RootSchema -ObjectPath "${ObjectPath}.${Key}" -SchemaPath "${SchemaPath}/properties/${ExactKey}" -ValidatePropertyNames:$ValidatePropertyNames -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth))
          continue
        }

        $ExpectedKey = $Schema['properties'].Keys | Where-Object { $_ -ieq $Key } | Select-Object -First 1
        if ($ValidatePropertyNames -and $ExpectedKey) {
          $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword properties -Reason PropertyNameCase -Message "Property '${Key}' has incorrect casing; expected '${ExpectedKey}'." -Field $Key -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/properties"))
          $Diagnostics.AddRange(@(Invoke-YamlSchemaNodeValidation -InputObject $InputObject[$Key] -Schema $Schema['properties'][$ExpectedKey] -RootSchema $RootSchema -ObjectPath "${ObjectPath}.${Key}" -SchemaPath "${SchemaPath}/properties/${ExpectedKey}" -ValidatePropertyNames:$ValidatePropertyNames -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth))
        } elseif ($ValidatePropertyNames -or ($Schema.Contains('additionalProperties') -and $Schema['additionalProperties'] -eq $false)) {
          $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword properties -Reason UnknownProperty -Message "Property '${Key}' is not defined by the schema." -Field $Key -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/properties"))
        }
      }
    }
  } elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    $Items = @($InputObject)
    if ($Schema.Contains('minItems') -and $Items.Count -lt [int]$Schema['minItems']) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword minItems -Reason TooFewItems -Message "Array contains fewer than $($Schema['minItems']) items." -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/minItems"))
    }
    if ($Schema.Contains('maxItems') -and $Items.Count -gt [int]$Schema['maxItems']) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword maxItems -Reason TooManyItems -Message "Array contains more than $($Schema['maxItems']) items." -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/maxItems"))
    }
    if ($Schema.Contains('uniqueItems') -and $Schema['uniqueItems']) {
      for ($LeftIndex = 0; $LeftIndex -lt $Items.Count; $LeftIndex++) {
        for ($RightIndex = $LeftIndex + 1; $RightIndex -lt $Items.Count; $RightIndex++) {
          if (Test-YamlSchemaValueEqual -Left $Items[$LeftIndex] -Right $Items[$RightIndex]) {
            $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword uniqueItems -Reason DuplicateItem -Message 'Array items must be unique.' -Value $Items[$RightIndex] -ObjectPath "${ObjectPath}[${RightIndex}]" -SchemaPath "${SchemaPath}/uniqueItems"))
          }
        }
      }
    }
    if ($Schema.Contains('items')) {
      for ($Index = 0; $Index -lt $Items.Count; $Index++) {
        $Diagnostics.AddRange(@(Invoke-YamlSchemaNodeValidation -InputObject $Items[$Index] -Schema $Schema['items'] -RootSchema $RootSchema -ObjectPath "${ObjectPath}[${Index}]" -SchemaPath "${SchemaPath}/items" -ValidatePropertyNames:$ValidatePropertyNames -ReferenceStack $ReferenceStack -Depth ($Depth + 1) -MaximumDepth $MaximumDepth))
      }
    }
  } elseif ($InputObject -is [string]) {
    if ($Schema.Contains('minLength') -and $InputObject.Length -lt [int]$Schema['minLength']) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword minLength -Reason TooShort -Message "String is shorter than $($Schema['minLength']) characters." -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/minLength"))
    }
    if ($Schema.Contains('maxLength') -and $InputObject.Length -gt [int]$Schema['maxLength']) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword maxLength -Reason TooLong -Message "String is longer than $($Schema['maxLength']) characters." -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/maxLength"))
    }
    if ($Schema.Contains('pattern') -and $InputObject -notmatch [string]$Schema['pattern']) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword pattern -Reason PatternMismatch -Message 'String does not match the required pattern.' -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/pattern"))
    }
    if ($Schema.Contains('format') -and $Schema['format'] -ceq 'date') {
      $ParsedDate = [datetime]::MinValue
      if (-not [datetime]::TryParseExact($InputObject, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$ParsedDate)) {
        $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword format -Reason InvalidDate -Message 'String is not a valid ISO date.' -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/format"))
      }
    }
  } elseif ($InputObject -is [ValueType] -and $InputObject -isnot [bool]) {
    if ($Schema.Contains('minimum') -and $InputObject -lt $Schema['minimum']) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword minimum -Reason BelowMinimum -Message "Number is below the minimum $($Schema['minimum'])." -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/minimum"))
    }
    if ($Schema.Contains('maximum') -and $InputObject -gt $Schema['maximum']) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword maximum -Reason AboveMaximum -Message "Number is above the maximum $($Schema['maximum'])." -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/maximum"))
    }
    if ($Schema.Contains('format') -and $Schema['format'] -ceq 'long' -and $InputObject -isnot [long] -and $InputObject -isnot [int] -and $InputObject -isnot [short] -and $InputObject -isnot [byte]) {
      $Diagnostics.Add((New-YamlSchemaDiagnostic -Keyword format -Reason InvalidLong -Message 'Value is not a signed integer.' -Value $InputObject -ObjectPath $ObjectPath -SchemaPath "${SchemaPath}/format"))
    }
  }

  return $Diagnostics.ToArray()
}

function Get-YamlSchemaValidationResult {
  <#
  .SYNOPSIS
    Validate a PowerShell object against a JSON Schema document.
  .PARAMETER InputObject
    The object to validate.
  .PARAMETER Schema
    The schema node applied to the input object.
  .PARAMETER RootSchema
    The root schema used to resolve local references. Defaults to Schema.
  .PARAMETER ObjectPath
    Initial JSONPath-like object location.
  .PARAMETER SchemaPath
    Initial JSON Pointer schema location.
  .PARAMETER ValidatePropertyNames
    Report unknown and incorrectly cased object properties.
  .PARAMETER MaximumDepth
    Maximum validation recursion depth.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][AllowNull()]$InputObject,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Schema,
    [System.Collections.IDictionary]$RootSchema = $Schema,
    [string]$ObjectPath = '$',
    [string]$SchemaPath = '#',
    [switch]$ValidatePropertyNames,
    [ValidateRange(1, 1024)][int]$MaximumDepth = 128
  )

  process {
    $Stack = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $Diagnostics = @(Invoke-YamlSchemaNodeValidation -InputObject $InputObject -Schema $Schema -RootSchema $RootSchema -ObjectPath $ObjectPath -SchemaPath $SchemaPath -ValidatePropertyNames:$ValidatePropertyNames -ReferenceStack $Stack -Depth 0 -MaximumDepth $MaximumDepth)
    return [pscustomobject]@{
      PSTypeName  = 'Dumplings.YamlSchema.ValidationResult'
      IsValid     = $Diagnostics.Count -eq 0
      Diagnostics = $Diagnostics
    }
  }
}

function Test-YamlObject {
  <#
  .SYNOPSIS
    Test whether a PowerShell object satisfies a JSON Schema node.
  .PARAMETER InputObject
    The object to validate.
  .PARAMETER Schema
    The schema node applied to the object.
  .PARAMETER Recurse
    Retained for compatibility; structured validation is always recursive.
  .PARAMETER ValidatePropertyNames
    Report unknown and incorrectly cased object properties.
  .PARAMETER PassThru
    Return the structured validation result instead of a Boolean.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][AllowNull()]$InputObject,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Schema,
    [switch]$Recurse,
    [switch]$ValidatePropertyNames,
    [switch]$PassThru
  )

  process {
    $Result = Get-YamlSchemaValidationResult -InputObject $InputObject -Schema $Schema -ValidatePropertyNames:$ValidatePropertyNames
    if ($PassThru) { return $Result }
    return $Result.IsValid
  }
}

function ConvertTo-SortedYamlObject {
  <#
  .SYNOPSIS
    Order dictionary keys according to a schema without changing values.
  .DESCRIPTION
    Known keys follow schema order, unknown keys retain their input order, and
    arrays retain their original order. Validation is intentionally separate.
  .PARAMETER InputObject
    The object to copy and order.
  .PARAMETER Schema
    The schema that supplies property ordering and child schemas.
  .PARAMETER Culture
    Retained for API compatibility; array sorting is no longer performed.
  .PARAMETER RootSchema
    Root schema used to resolve local references during recursive ordering.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][AllowNull()]$InputObject,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Schema,
    [cultureinfo]$Culture = (Get-Culture),
    [Parameter(DontShow)][System.Collections.IDictionary]$RootSchema = $Schema
  )

  process {
    if ($Schema.Contains('$ref')) {
      $Schema = Get-YamlSchemaValue -InputObject $RootSchema -Ref $Schema['$ref']
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
      $Output = [ordered]@{}
      if ($Schema.Contains('properties')) {
        foreach ($Key in $Schema['properties'].Keys) {
          if ($InputObject.Contains($Key)) {
            $Output[$Key] = ConvertTo-SortedYamlObject -InputObject $InputObject[$Key] -Schema $Schema['properties'][$Key] -Culture $Culture -RootSchema $RootSchema
          }
        }
      }
      # Formatting must never discard extension or misspelled fields; schema
      # validation remains responsible for reporting them to the caller.
      foreach ($Key in $InputObject.Keys) {
        if (-not $Output.Contains($Key)) { $Output[$Key] = Copy-YamlSchemaObject -InputObject $InputObject[$Key] }
      }
      return $Output
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
      $ItemSchema = $Schema.Contains('items') ? $Schema['items'] : [ordered]@{}
      return , @($InputObject | ForEach-Object { ConvertTo-SortedYamlObject -InputObject $_ -Schema $ItemSchema -Culture $Culture -RootSchema $RootSchema })
    }
    return $InputObject
  }
}

Export-ModuleMember -Function Get-YamlSchemaValue, Expand-YamlSchema, Get-YamlSchemaValidationResult, Test-YamlObject, ConvertTo-SortedYamlObject
