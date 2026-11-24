# SPDX-License-Identifier: Apache-2.0
# Shared static command-line resolution for executable bootstrapper families.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Split-BootstrapperCommandLine {
  <#
  .SYNOPSIS
    Split a Windows-style bootstrapper command line without executing it
  .PARAMETER CommandLine
    The command line to split
  .PARAMETER IncludeExtent
    Return Value, Start, and Length for each token. Offsets are UTF-16 positions
    in the original string, allowing callers to preserve a raw argument tail.
  #>
  [OutputType([string[]], [pscustomobject[]])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$CommandLine, [switch]$IncludeExtent)

  $Arguments = $IncludeExtent ? [Collections.Generic.List[object]]::new() : [Collections.Generic.List[string]]::new()
  $Builder = [Text.StringBuilder]::new()
  $InQuotes = $false
  $Index = 0
  $TokenStart = -1
  while ($Index -lt $CommandLine.Length) {
    $Character = $CommandLine[$Index]
    if ([char]::IsWhiteSpace($Character) -and -not $InQuotes) {
      if ($Builder.Length -gt 0 -or ($IncludeExtent -and $TokenStart -ge 0)) {
        if ($IncludeExtent) { $Arguments.Add([pscustomobject]@{ Value = $Builder.ToString(); Start = $TokenStart; Length = $Index - $TokenStart }) } else { $Arguments.Add($Builder.ToString()) }
        $null = $Builder.Clear()
      }
      $TokenStart = -1
      $Index++
      continue
    }
    if ($TokenStart -lt 0) { $TokenStart = $Index }
    if ($Character -eq '"') {
      $InQuotes = -not $InQuotes
      $Index++
      continue
    }
    if ($Character -eq '\') {
      $SlashCount = 0
      while ($Index -lt $CommandLine.Length -and $CommandLine[$Index] -eq '\') {
        $SlashCount++
        $Index++
      }
      if ($Index -lt $CommandLine.Length -and $CommandLine[$Index] -eq '"') {
        $null = $Builder.Append('\', [Math]::Floor($SlashCount / 2))
        if (($SlashCount % 2) -eq 0) { $InQuotes = -not $InQuotes } else { $null = $Builder.Append('"') }
        $Index++
      } else {
        $null = $Builder.Append('\', $SlashCount)
      }
      continue
    }
    $null = $Builder.Append($Character)
    $Index++
  }
  if ($Builder.Length -gt 0 -or ($IncludeExtent -and $TokenStart -ge 0)) {
    if ($IncludeExtent) { $Arguments.Add([pscustomobject]@{ Value = $Builder.ToString(); Start = $TokenStart; Length = $Index - $TokenStart }) } else { $Arguments.Add($Builder.ToString()) }
  }
  return @($Arguments)
}

function Find-BootstrapperCandidatePath {
  <#
  .SYNOPSIS
    Match one command token to a deterministic embedded or supplied payload path.
  .PARAMETER CandidatePath
    Logical archive paths or resolved companion-file paths available to the wrapper.
  .PARAMETER Token
    Payload token from the configured command line.
  .OUTPUTS
    A result containing the selected path, resolution kind, and every ambiguous candidate.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowEmptyCollection()][string[]]$CandidatePath = @(),
    [AllowNull()][AllowEmptyString()][string]$Token
  )

  if ([string]::IsNullOrWhiteSpace($Token)) {
    return [pscustomobject]@{ Path = $null; Kind = 'None'; Matches = @() }
  }

  $NormalizedToken = $Token.Replace('/', '\').Trim('"')
  $NormalizedCandidates = [Collections.Generic.List[object]]::new()
  foreach ($Path in $CandidatePath) {
    if ([string]::IsNullOrWhiteSpace($Path)) { continue }
    $NormalizedCandidates.Add([pscustomobject]@{ Original = $Path; Normalized = $Path.Replace('/', '\').Trim('"') })
  }

  # Archive-relative paths are authoritative when the command line names them
  # exactly. This also preserves the historical behavior for ordinary wrappers.
  $CandidateMatches = @($NormalizedCandidates | Where-Object { $_.Normalized.Equals($NormalizedToken, [StringComparison]::OrdinalIgnoreCase) })
  if ($CandidateMatches.Count -eq 1) { return [pscustomobject]@{ Path = $CandidateMatches[0].Original; Kind = 'Exact'; Matches = @($CandidateMatches.Original) } }
  if ($CandidateMatches.Count -gt 1) { return [pscustomobject]@{ Path = $null; Kind = 'Ambiguous'; Matches = @($CandidateMatches.Original) } }

  # Supplied companion files are represented by resolved host paths. Match the
  # configured relative path against their trailing segments before falling
  # back to a basename, allowing x86\setup.msi and x64\setup.msi to coexist.
  $Suffix = '\' + $NormalizedToken.TrimStart('\')
  $CandidateMatches = @($NormalizedCandidates | Where-Object { $_.Normalized.EndsWith($Suffix, [StringComparison]::OrdinalIgnoreCase) })
  if ($CandidateMatches.Count -eq 1) { return [pscustomobject]@{ Path = $CandidateMatches[0].Original; Kind = 'Suffix'; Matches = @($CandidateMatches.Original) } }
  if ($CandidateMatches.Count -gt 1) { return [pscustomobject]@{ Path = $null; Kind = 'Ambiguous'; Matches = @($CandidateMatches.Original) } }

  $LeafName = [IO.Path]::GetFileName($NormalizedToken)
  $CandidateMatches = @($NormalizedCandidates | Where-Object { [IO.Path]::GetFileName($_.Normalized).Equals($LeafName, [StringComparison]::OrdinalIgnoreCase) })
  if ($CandidateMatches.Count -eq 1) { return [pscustomobject]@{ Path = $CandidateMatches[0].Original; Kind = 'FileName'; Matches = @($CandidateMatches.Original) } }
  if ($CandidateMatches.Count -gt 1) { return [pscustomobject]@{ Path = $null; Kind = 'Ambiguous'; Matches = @($CandidateMatches.Original) } }
  return [pscustomobject]@{ Path = $null; Kind = 'NotFound'; Matches = @() }
}

function Resolve-BootstrapperCommand {
  <#
  .SYNOPSIS
    Resolve the nested payload referenced by a bootstrapper command
  .PARAMETER CommandLine
    The exact configured command line
  .PARAMETER CandidatePath
    Paths available in the embedded archive or cabinet
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$CommandLine,
    [string[]]$CandidatePath = @()
  )

  $Tokens = @(Split-BootstrapperCommandLine -CommandLine $CommandLine)
  $PayloadTokenIndex = if ($Tokens.Count -gt 0) { 0 } else { -1 }
  $Launcher = if ($Tokens.Count -gt 0) { [IO.Path]::GetFileName($Tokens[0]).ToLowerInvariant() } else { $null }
  if ($Launcher -in @('msiexec', 'msiexec.exe')) {
    for ($Index = 1; $Index -lt $Tokens.Count - 1; $Index++) {
      if ($Tokens[$Index] -match '^(?i)/(i|package|p)$') {
        $PayloadTokenIndex = $Index + 1
        break
      }
      if ($Tokens[$Index] -match '^(?i)/(i|package|p)(.+)$') {
        $Tokens = @($Tokens[0..($Index - 1)]) + @($Matches[2]) + @($Tokens[($Index + 1)..($Tokens.Count - 1)])
        $PayloadTokenIndex = $Index
        break
      }
    }
  }

  $PayloadToken = if ($PayloadTokenIndex -ge 0 -and $PayloadTokenIndex -lt $Tokens.Count) { $Tokens[$PayloadTokenIndex] } else { $null }
  $SelectedPath = $null
  $ResolutionKind = 'None'
  $CandidateMatches = @()
  if ($PayloadToken) {
    $Resolution = Find-BootstrapperCandidatePath -CandidatePath $CandidatePath -Token $PayloadToken
    $SelectedPath = $Resolution.Path
    $ResolutionKind = $Resolution.Kind
    $CandidateMatches = @($Resolution.Matches)
  }
  if (-not $SelectedPath -and $ResolutionKind -ne 'Ambiguous') {
    for ($Index = 1; $Index -lt $Tokens.Count; $Index++) {
      $Resolution = Find-BootstrapperCandidatePath -CandidatePath $CandidatePath -Token $Tokens[$Index]
      if ($Resolution.Kind -eq 'Ambiguous') {
        $ResolutionKind = 'Ambiguous'
        $CandidateMatches = @($Resolution.Matches)
        break
      }
      if ($Resolution.Path) {
        $SelectedPath = $Resolution.Path
        $ResolutionKind = $Resolution.Kind
        $CandidateMatches = @($Resolution.Matches)
        $PayloadToken = $Tokens[$Index]
        $PayloadTokenIndex = $Index
        break
      }
    }
  }

  $ArgumentList = if ($PayloadTokenIndex -ge 0 -and $PayloadTokenIndex + 1 -lt $Tokens.Count) {
    @($Tokens[($PayloadTokenIndex + 1)..($Tokens.Count - 1)])
  } else {
    @()
  }

  [pscustomobject]@{
    CommandLine      = $CommandLine
    Launcher         = if ($Tokens.Count -gt 0) { $Tokens[0] } else { $null }
    PayloadReference = $PayloadToken
    ExecutedPayload  = $SelectedPath
    ArgumentList     = $ArgumentList
    IsResolved       = [bool]$SelectedPath
    ResolutionKind   = $ResolutionKind
    CandidateMatches = $CandidateMatches
  }
}

Export-ModuleMember -Function Split-BootstrapperCommandLine, Resolve-BootstrapperCommand
