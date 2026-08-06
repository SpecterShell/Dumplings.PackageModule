# SPDX-License-Identifier: MIT
# This shared source is kept byte-identical in PackageModule and InstallerParsers.

# Condition projection and registry association evidence are shared parser mechanics.
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

# SPDX-License-Identifier: MIT
# Static Windows protocol and file-extension association helpers. These
# functions interpret explicit registry writes only; they never query or modify
# the local registry and never infer associations from arbitrary strings.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function ConvertTo-InstallerClassRegistryWrite {
  <#
  .SYNOPSIS
    Normalize an explicit registry write beneath Windows Classes roots
  .PARAMETER RegistryWrite
    Static registry-write evidence containing Root, Key, Name, Value, and Type fields; the input object is not modified.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$RegistryWrite)

  $Root = [string]$RegistryWrite.Root
  $Key = [string]$RegistryWrite.Key
  if ($Key -match '^(?<Root>HKEY_CLASSES_ROOT|HKCR|HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU)\\?(?<Key>.*)$') {
    $Root = $Matches.Root
    $Key = $Matches.Key
  }
  $NormalizedRoot = switch -Regex ($Root) {
    '^(HKEY_CLASSES_ROOT|HKCR|0)$' { 'HKCR'; break }
    '^(HKEY_CURRENT_USER|HKCU|1)$' { 'HKCU'; break }
    '^(HKEY_LOCAL_MACHINE|HKLM|2)$' { 'HKLM'; break }
    default { return $null }
  }

  $RelativeKey = if ($NormalizedRoot -eq 'HKCR') {
    $Key -replace '^(?i:Software\\Classes\\?)', ''
  } elseif ($Key -match '^(?i:Software\\Classes\\)(?<Key>.+)$') {
    $Matches.Key
  } else {
    return $null
  }
  $RelativeKey = $RelativeKey.Trim('\\')
  if ([string]::IsNullOrWhiteSpace($RelativeKey)) { return $null }

  [pscustomobject]@{
    Root        = $NormalizedRoot
    RelativeKey = $RelativeKey
    Name        = $RegistryWrite.Name
    Value       = if ($RegistryWrite.PSObject.Properties['Value']) { $RegistryWrite.Value } elseif ($RegistryWrite.PSObject.Properties['Data']) { $RegistryWrite.Data } else { $null }
    Type        = $RegistryWrite.Type
    Source      = $RegistryWrite
  }
}

function Test-InstallerDefaultRegistryValueName {
  <#
  .SYNOPSIS
    Test whether a registry-write name denotes the key's default value.
  .PARAMETER Name
    Registry value name. Null, empty, `(Default)`, `@`, and `*` are treated as the default value.
  #>
  [OutputType([bool])]
  param([AllowNull()][object]$Name)
  return $null -eq $Name -or [string]::IsNullOrWhiteSpace([string]$Name) -or [string]$Name -in @('(Default)', '@', '*')
}

function Get-InstallerClassDefaultValue {
  <#
  .SYNOPSIS
    Read the last explicit default-value write for one normalized Classes key.
  .PARAMETER RegistryWrite
    Normalized explicit class registry writes; the input collection is not modified.
  .PARAMETER Root
    Normalized HKCR, HKCU, or HKLM root to match.
  .PARAMETER RelativeKey
    Path relative to the selected Classes root.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][object[]]$RegistryWrite,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$RelativeKey
  )
  $Write = @($RegistryWrite | Where-Object {
      $_.Root -eq $Root -and $_.RelativeKey -ieq $RelativeKey -and (Test-InstallerDefaultRegistryValueName -Name $_.Name)
    } | Select-Object -Last 1)
  if ($Write.Count -eq 0 -or $null -eq $Write[0].Value) { return $null }
  $Value = [string]$Write[0].Value
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value
}

function Get-InstallerRegistryAssociationInfo {
  <#
  .SYNOPSIS
    Extract protocol and file-extension associations from explicit registry writes
  .DESCRIPTION
    Supports HKCR and HKLM/HKCU Software\Classes writes. Protocols require an
    explicit URL Protocol value. File extensions are resolved from their default
    ProgID and OpenWithProgids values, or from a command written directly below
    the extension key, with optional open-command and icon data.
  .PARAMETER RegistryWrite
    Objects with Root, Key, Name, Value, and optional Type properties.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $ClassWrites = @($RegistryWrite | ForEach-Object {
      if ($null -ne $_) { ConvertTo-InstallerClassRegistryWrite -RegistryWrite $_ }
    } | Where-Object { $_ })
  $Warnings = [System.Collections.Generic.List[string]]::new()
  $ProtocolAssociations = [System.Collections.Generic.List[object]]::new()
  $FileExtensionAssociations = [System.Collections.Generic.List[object]]::new()
  $SeenProtocols = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $SeenExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  foreach ($Write in @($ClassWrites | Where-Object {
        $_.RelativeKey.IndexOf('\') -lt 0 -and [string]$_.Name -ieq 'URL Protocol'
      })) {
    $Protocol = $Write.RelativeKey.Trim()
    if ($Protocol -notmatch '^[A-Za-z][A-Za-z0-9+.-]{0,254}$') {
      $Warnings.Add("Ignored non-literal protocol key '$Protocol'.")
      continue
    }
    $Identity = "$($Write.Root)`0$Protocol"
    if (-not $SeenProtocols.Add($Identity)) { continue }
    $Command = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Write.Root -RelativeKey "$Protocol\shell\open\command"
    if ([string]::IsNullOrWhiteSpace($Command)) { $Warnings.Add("Protocol '$Protocol' has URL Protocol evidence but no literal open command.") }
    $ProtocolAssociations.Add([pscustomobject]@{
        Protocol    = $Protocol.ToLowerInvariant()
        Root        = $Write.Root
        Description = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Write.Root -RelativeKey $Protocol
        Command     = $Command
        DefaultIcon = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Write.Root -RelativeKey "$Protocol\DefaultIcon"
        Evidence    = @($Write.Source)
      })
  }

  $ExtensionKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Write in $ClassWrites) {
    if ($Write.RelativeKey -match '^(?<Extension>\.[^\\]+)(?:\\OpenWithProgids)?$') {
      $null = $ExtensionKeys.Add("$($Write.Root)`0$($Matches.Extension)")
    }
  }
  foreach ($Identity in $ExtensionKeys) {
    $Parts = $Identity -split [char]0, 2
    $Root = $Parts[0]
    $Extension = $Parts[1]
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
      $Warnings.Add("Ignored non-literal file extension key '$Extension'.")
      continue
    }
    if (-not $SeenExtensions.Add($Identity)) { continue }
    $ProgIds = [System.Collections.Generic.List[string]]::new()
    $DefaultProgId = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey $Extension
    if ($DefaultProgId) { $ProgIds.Add($DefaultProgId) }
    foreach ($Write in @($ClassWrites | Where-Object {
          $_.Root -eq $Root -and $_.RelativeKey -ieq "$Extension\OpenWithProgids" -and -not (Test-InstallerDefaultRegistryValueName -Name $_.Name)
        })) {
      $ProgId = [string]$Write.Name
      if (-not [string]::IsNullOrWhiteSpace($ProgId) -and -not $ProgIds.Contains($ProgId)) { $ProgIds.Add($ProgId) }
    }
    $PrimaryProgId = $ProgIds | Select-Object -First 1
    # Some installers register verbs directly below .ext instead of creating a separate ProgID.
    # Preserve that valid shell association and warn only when neither registration form is complete.
    $DirectCommand = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey "$Extension\shell\open\command"
    $DirectIcon = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey "$Extension\DefaultIcon"
    if (-not $PrimaryProgId -and -not $DirectCommand) {
      $Warnings.Add("File extension '$Extension' has neither a literal ProgID nor a direct open command.")
    }
    $FileExtensionAssociations.Add([pscustomobject]@{
        FileExtension = $Extension.TrimStart('.').ToLowerInvariant()
        Extension     = $Extension.ToLowerInvariant()
        Root          = $Root
        DefaultProgId = $DefaultProgId
        ProgIds       = @($ProgIds)
        Description   = if ($PrimaryProgId) { Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey $PrimaryProgId } else { $null }
        Command       = if ($PrimaryProgId) { Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey "$PrimaryProgId\shell\open\command" } else { $DirectCommand }
        DefaultIcon   = if ($PrimaryProgId) { Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey "$PrimaryProgId\DefaultIcon" } else { $DirectIcon }
        Evidence      = @($ClassWrites | Where-Object { $_.Root -eq $Root -and $_.RelativeKey -match "^(?i:$([regex]::Escape($Extension)))(?:\\|$)" } | ForEach-Object Source)
      })
  }

  [pscustomobject]@{
    Protocols                 = @($ProtocolAssociations | Select-Object -ExpandProperty Protocol -Unique | Sort-Object)
    FileExtensions            = @($FileExtensionAssociations | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    ProtocolAssociations      = @($ProtocolAssociations)
    FileExtensionAssociations = @($FileExtensionAssociations)
    RegistryWrites            = @($ClassWrites | ForEach-Object Source)
    Warnings                  = @($Warnings | Select-Object -Unique)
  }
}

Export-ModuleMember -Function Merge-InstallerConditionState, Resolve-InstallerBooleanExpression, Get-InstallerRegistryAssociationInfo
