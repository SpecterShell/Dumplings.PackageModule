# SPDX-License-Identifier: Apache-2.0

function Merge-InstallerConditionState {
  <#
  .SYNOPSIS
    Merge bounded True, False, and Unknown condition states.
  .PARAMETER State
    Child states to merge. Empty All and None groups are true; an empty Any group is false.
  .PARAMETER Operator
    All requires every child, Any requires one child, and None rejects every true child.
  #>
  [OutputType([string])]
  param (
    [AllowEmptyCollection()][ValidateSet('True', 'False', 'Unknown')][string[]]$State = @(),
    [Parameter(Mandatory)][ValidateSet('All', 'Any', 'None')][string]$Operator
  )

  switch ($Operator) {
    'All' {
      if ($State -contains 'False') { return 'False' }
      if ($State -contains 'Unknown') { return 'Unknown' }
      return 'True'
    }
    'Any' {
      if ($State -contains 'True') { return 'True' }
      if ($State -contains 'Unknown') { return 'Unknown' }
      return 'False'
    }
    'None' {
      if ($State -contains 'True') { return 'False' }
      if ($State -contains 'Unknown') { return 'Unknown' }
      return 'True'
    }
  }
}

function Resolve-InstallerBooleanExpression {
  <#
  .SYNOPSIS
    Evaluate a bounded Boolean expression using explicit three-valued identifier states.
  .DESCRIPTION
    Supports identifiers, true/false literals, !, &&, ||, and parentheses. Missing
    identifiers remain Unknown; this function never reads host registry, files, or platform
    state to fill missing evidence.
  .PARAMETER Expression
    The serialized Boolean expression.
  .PARAMETER IdentifierState
    Identifier-to-state dictionary. Values may be True/False/Unknown strings or objects with
    State and optional Reason/Reasons properties.
  .PARAMETER MaximumTokenCount
    Maximum number of lexical tokens accepted before evaluation is rejected.
  .PARAMETER MaximumDepth
    Maximum parenthesis and unary-negation recursion depth.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Expression,
    [Parameter(Mandatory)][System.Collections.IDictionary]$IdentifierState,
    [ValidateRange(1, 65536)][int]$MaximumTokenCount = 256,
    [ValidateRange(1, 1024)][int]$MaximumDepth = 32
  )

  $TokenMatches = [regex]::Matches($Expression, '\s*(?<Token>\&\&|\|\||!|\(|\)|[A-Za-z_][A-Za-z0-9_.:-]*)')
  $Tokens = [string[]]@($TokenMatches | ForEach-Object { $_.Groups['Token'].Value })
  $CompactExpression = [regex]::Replace($Expression, '\s+', '')
  if ($Tokens.Count -eq 0 -or ($Tokens -join '') -cne $CompactExpression -or $Tokens.Count -gt $MaximumTokenCount) {
    return [pscustomobject][ordered]@{
      State              = 'Unknown'
      Identifiers        = [string[]]@()
      UnknownIdentifiers = [string[]]@()
      Reasons            = [string[]]@("The Boolean expression contains unsupported syntax or exceeds the $MaximumTokenCount-token limit.")
    }
  }

  $Parser = [pscustomobject]@{ Index = 0; Depth = 0 }
  $Reasons = [Collections.Generic.List[string]]::new()
  $Identifiers = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $UnknownIdentifiers = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  # Resolve dictionary keys explicitly because callers may provide case-sensitive dictionaries.
  $GetIdentifierValue = {
    param([string]$Name)
    foreach ($Key in $IdentifierState.Keys) {
      if ([string]$Key -ieq $Name) { return [pscustomobject]@{ Found = $true; Value = $IdentifierState[$Key] } }
    }
    return [pscustomobject]@{ Found = $false; Value = $null }
  }

  $ParseOr = $null
  $ParsePrimary = {
    $Parser.Depth++
    if ($Parser.Depth -gt $MaximumDepth) { throw "The Boolean expression exceeds the $MaximumDepth-level parser limit." }
    try {
      if ($Parser.Index -ge $Tokens.Count) { throw 'The Boolean expression ended unexpectedly.' }
      $Token = $Tokens[$Parser.Index++]
      if ($Token -eq '(') {
        $State = & $ParseOr
        if ($Parser.Index -ge $Tokens.Count -or $Tokens[$Parser.Index++] -ne ')') { throw 'The Boolean expression has an unmatched opening parenthesis.' }
        return $State
      }
      if ($Token -in @(')', '&&', '||')) { throw "Unexpected token '$Token' in the Boolean expression." }
      if ($Token -ieq 'true') { return 'True' }
      if ($Token -ieq 'false') { return 'False' }

      $null = $Identifiers.Add($Token)
      $Resolved = & $GetIdentifierValue $Token
      if (-not $Resolved.Found) {
        $null = $UnknownIdentifiers.Add($Token)
        $Reasons.Add("Identifier '$Token' has no static state.")
        return 'Unknown'
      }
      $Value = $Resolved.Value
      $State = if ($Value -is [string]) { [string]$Value } elseif ($Value.PSObject.Properties['State']) { [string]$Value.State } else { 'Unknown' }
      if ($State -notin @('True', 'False', 'Unknown')) {
        $Reasons.Add("Identifier '$Token' has unsupported state '$State'.")
        $State = 'Unknown'
      }
      foreach ($Reason in @($Value.PSObject.Properties['Reasons'] ? $Value.Reasons : $Value.PSObject.Properties['Reason'] ? $Value.Reason : @())) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Reason)) { $Reasons.Add([string]$Reason) }
      }
      if ($State -eq 'Unknown') { $null = $UnknownIdentifiers.Add($Token) }
      return $State
    } finally {
      $Parser.Depth--
    }
  }
  $ParseNot = {
    if ($Parser.Index -lt $Tokens.Count -and $Tokens[$Parser.Index] -eq '!') {
      $Parser.Index++
      $Parser.Depth++
      if ($Parser.Depth -gt $MaximumDepth) { throw "The Boolean expression exceeds the $MaximumDepth-level parser limit." }
      try {
        $State = & $ParseNot
      } finally {
        $Parser.Depth--
      }
      return $State -eq 'True' ? 'False' : ($State -eq 'False' ? 'True' : 'Unknown')
    }
    return & $ParsePrimary
  }
  $ParseAnd = {
    $State = & $ParseNot
    while ($Parser.Index -lt $Tokens.Count -and $Tokens[$Parser.Index] -eq '&&') {
      $Parser.Index++
      $State = Merge-InstallerConditionState -State @($State, (& $ParseNot)) -Operator All
    }
    return $State
  }
  $ParseOr = {
    $State = & $ParseAnd
    while ($Parser.Index -lt $Tokens.Count -and $Tokens[$Parser.Index] -eq '||') {
      $Parser.Index++
      $State = Merge-InstallerConditionState -State @($State, (& $ParseAnd)) -Operator Any
    }
    return $State
  }

  try {
    $State = & $ParseOr
    if ($Parser.Index -ne $Tokens.Count) { throw "Unexpected token '$($Tokens[$Parser.Index])' in the Boolean expression." }
  } catch {
    $State = 'Unknown'
    $Reasons.Add($_.Exception.Message)
  }
  return [pscustomobject][ordered]@{
    State              = $State
    Identifiers        = [string[]]@($Identifiers | Sort-Object)
    UnknownIdentifiers = [string[]]@($UnknownIdentifiers | Sort-Object)
    Reasons            = [string[]]@($Reasons | Select-Object -Unique)
  }
}

Export-ModuleMember -Function Merge-InstallerConditionState, Resolve-InstallerBooleanExpression
