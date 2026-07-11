# SPDX-License-Identifier: MIT

function Import-CabinetDependency {
  <#
  .SYNOPSIS
    Load the bundled Microsoft cabinet reader
  #>
  if (-not ([Management.Automation.PSTypeName]'Microsoft.Deployment.Compression.Cab.CabInfo').Type) {
    foreach ($AssemblyName in @('Microsoft.Deployment.Compression.dll', 'Microsoft.Deployment.Compression.Cab.dll')) {
      $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', $AssemblyName
      if (-not (Test-Path -LiteralPath $AssemblyPath)) { throw "The cabinet dependency is missing: $AssemblyPath" }
      Add-Type -Path $AssemblyPath
    }
  }
}

function Get-CabinetEntry {
  <#
  .SYNOPSIS
    Enumerate files in a cabinet without extracting them
  .PARAMETER Path
    The path to the cabinet
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string[]]$Path)

  Import-CabinetDependency
  $ArchivePaths = [Collections.Generic.List[string]]::new()
  foreach ($ArchivePath in $Path) { $ArchivePaths.Add((Get-Item -LiteralPath $ArchivePath -Force).FullName) }
  if ($ArchivePaths.Count -eq 1) {
    $Cabinet = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($ArchivePaths[0])
    $Entries = $Cabinet.GetFiles()
  } else {
    $Context = [Microsoft.Deployment.Compression.ArchiveFileStreamContext]::new($ArchivePaths, $null, $null)
    $Engine = [Microsoft.Deployment.Compression.Cab.CabEngine]::new()
    try { $Entries = $Engine.GetFileInfo($Context, $null) } finally { $Engine.Dispose() }
  }
  foreach ($Entry in $Entries) {
    [pscustomobject]@{
      FullName = [string]$Entry.Name
      Length   = [long]$Entry.Length
    }
  }
}

function Export-CabinetEntry {
  <#
  .SYNOPSIS
    Export selected cabinet entries with path and output limits
  .PARAMETER Path
    The path to the cabinet
  .PARAMETER DestinationPath
    The extraction destination
  .PARAMETER Name
    The archive-path wildcard to export
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][string[]]$Path,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )

  Import-CabinetDependency
  $ArchivePaths = [Collections.Generic.List[string]]::new()
  foreach ($ArchivePath in $Path) { $ArchivePaths.Add((Get-Item -LiteralPath $ArchivePath -Force).FullName) }
  $Entries = @(Get-CabinetEntry -Path $ArchivePaths | Where-Object { Test-ExtractionPattern -Path $_.FullName -Pattern $Name })
  $TotalLength = [long](($Entries | Measure-Object -Property Length -Sum).Sum)
  if ($TotalLength -gt $MaximumExpandedBytes) { throw 'The selected cabinet entries exceed the configured output limit.' }

  $Results = [Collections.Generic.List[string]]::new()
  foreach ($Entry in $Entries) {
    $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
    $Parent = [IO.Path]::GetDirectoryName($OutputPath)
    if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
    $Results.Add($OutputPath)
  }
  if ($ArchivePaths.Count -eq 1 -and $Entries.Count -gt 0) {
    $Cabinet = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($ArchivePaths[0])
    foreach ($Index in 0..($Entries.Count - 1)) {
      $Cabinet.UnpackFile($Entries[$Index].FullName, $Results[$Index])
    }
  } elseif ($Entries.Count -gt 0) {
    $SelectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Entry in $Entries) { $null = $SelectedNames.Add($Entry.FullName) }
    $Predicate = [Predicate[string]] { param($EntryName) $SelectedNames.Contains($EntryName) }
    $Context = [Microsoft.Deployment.Compression.ArchiveFileStreamContext]::new($ArchivePaths, [IO.Path]::GetFullPath($DestinationPath), $null)
    $Engine = [Microsoft.Deployment.Compression.Cab.CabEngine]::new()
    try { $Engine.Unpack($Context, $Predicate) } finally { $Engine.Dispose() }
  }
  return @($Results)
}

Export-ModuleMember -Function Import-CabinetDependency, Get-CabinetEntry, Export-CabinetEntry
