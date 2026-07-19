# SPDX-License-Identifier: Apache-2.0

function Split-BootstrapperCommandLine {
  <#
  .SYNOPSIS
    Split a Windows-style bootstrapper command line without executing it
  .PARAMETER CommandLine
    The command line to split
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$CommandLine)

  $Arguments = [Collections.Generic.List[string]]::new()
  $Builder = [Text.StringBuilder]::new()
  $InQuotes = $false
  $Index = 0
  while ($Index -lt $CommandLine.Length) {
    $Character = $CommandLine[$Index]
    if ([char]::IsWhiteSpace($Character) -and -not $InQuotes) {
      if ($Builder.Length -gt 0) {
        $Arguments.Add($Builder.ToString())
        $null = $Builder.Clear()
      }
      $Index++
      continue
    }
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
  if ($Builder.Length -gt 0) { $Arguments.Add($Builder.ToString()) }
  return @($Arguments)
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
  $NormalizedToken = if ($PayloadToken) { $PayloadToken.Replace('/', '\').Trim('"') } else { $null }
  $SelectedPath = $null
  if ($NormalizedToken) {
    $SelectedPath = @($CandidatePath | Where-Object {
        $Candidate = $_.Replace('/', '\')
        $Candidate.Equals($NormalizedToken, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($Candidate).Equals([IO.Path]::GetFileName($NormalizedToken), [StringComparison]::OrdinalIgnoreCase)
      } | Sort-Object Length -Descending | Select-Object -First 1)[0]
  }
  if (-not $SelectedPath) {
    for ($Index = 1; $Index -lt $Tokens.Count; $Index++) {
      $Token = $Tokens[$Index].Replace('/', '\').Trim('"')
      $Candidate = @($CandidatePath | Where-Object {
          $CandidateValue = $_.Replace('/', '\')
          $CandidateValue.Equals($Token, [StringComparison]::OrdinalIgnoreCase) -or
          [IO.Path]::GetFileName($CandidateValue).Equals([IO.Path]::GetFileName($Token), [StringComparison]::OrdinalIgnoreCase)
        } | Sort-Object Length -Descending | Select-Object -First 1)[0]
      if ($Candidate) {
        $SelectedPath = $Candidate
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
  }
}

Export-ModuleMember -Function Split-BootstrapperCommandLine, Resolve-BootstrapperCommand
