# SPDX-License-Identifier: Apache-2.0
# Host/runtime source: https://github.com/dotnet/dotnet
# Streaming .NET apphost mechanics used by Portable.psm1 orchestration.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:DotNetHostMaximumBindingLength = 1024

function Get-PEDotNetAppHostBindingCandidateFromStream {
  <#
  .SYNOPSIS
    Find bounded apphost DLL binding candidates without buffering the PE image
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream)
  $Candidates = [Collections.Generic.List[string]]::new()
  $Needle = [Text.Encoding]::ASCII.GetBytes('.dll')
  foreach ($DllOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Needle -Maximum 4096)) {
    $WindowStart = [Math]::Max(0L, $DllOffset - $Script:DotNetHostMaximumBindingLength)
    $WindowLength = [int][Math]::Min(($Script:DotNetHostMaximumBindingLength * 2) + $Needle.Length, $Stream.Length - $WindowStart)
    $Window = Read-BinaryBytes -Stream $Stream -Offset $WindowStart -Count $WindowLength
    $LocalDllOffset = [int]($DllOffset - $WindowStart)
    $Start = $LocalDllOffset
    while ($Start -gt 0 -and $Window[$Start - 1] -ne 0 -and ($LocalDllOffset - $Start) -lt $Script:DotNetHostMaximumBindingLength) { $Start-- }
    $End = $LocalDllOffset + $Needle.Length
    while ($End -lt $Window.Length -and $Window[$End] -ne 0 -and ($End - $Start) -lt $Script:DotNetHostMaximumBindingLength) { $End++ }
    if ($End -le $Start -or $End - $Start -gt $Script:DotNetHostMaximumBindingLength) { continue }
    $Candidate = [Text.Encoding]::UTF8.GetString($Window, $Start, $End - $Start)
    if ($Candidate -notmatch '(?i)\.dll$' -or $Candidate -match '[\x00-\x1F]|[<>:"|?*]' -or $Candidate -match '^[A-Za-z]:[\\/]' -or $Candidate.StartsWith('\')) { continue }
    $Candidates.Add($Candidate)
  }
  return @($Candidates | Sort-Object -Unique)
}

Export-ModuleMember -Function Get-PEDotNetAppHostBindingCandidateFromStream
