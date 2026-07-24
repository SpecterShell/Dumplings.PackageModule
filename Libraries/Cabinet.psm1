# SPDX-License-Identifier: Apache-2.0

function Import-CabinetDependency {
  <#
  .SYNOPSIS
    Load the bundled Microsoft cabinet reader
  #>
  if (-not ([Management.Automation.PSTypeName]'Microsoft.Deployment.Compression.Cab.CabInfo').Type) {
    foreach ($AssemblyName in @('Microsoft.Deployment.Compression.dll', 'Microsoft.Deployment.Compression.Cab.dll')) {
      $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'Assemblies', $AssemblyName
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
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][string[]]$Path,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )

  Import-CabinetDependency
  $ArchivePaths = [Collections.Generic.List[string]]::new()
  foreach ($ArchivePath in $Path) { $ArchivePaths.Add((Resolve-InstallerFileSystemPath -Path $ArchivePath -PathType Leaf)) }
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $Entries = @(Get-CabinetEntry -Path $ArchivePaths | Where-Object { Test-ExtractionPattern -Path $_.FullName -Pattern $Name })
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $SelectedEntries = [Collections.Generic.List[object]]::new()
  $Results = [Collections.Generic.List[string]]::new()
  foreach ($Entry in $Entries) {
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.FullName `
      -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if (-not $Target.ShouldWrite) { continue }
    $SelectedEntries.Add([pscustomobject]@{ Entry = $Entry; Target = $Target })
  }
  $TotalLength = [long](($SelectedEntries.Entry | Measure-Object -Property Length -Sum).Sum)
  if ($TotalLength -gt $MaximumExpandedBytes) { throw 'The selected cabinet entries exceed the configured output limit.' }

  foreach ($SelectedEntry in $SelectedEntries) {
    $Parent = [IO.Path]::GetDirectoryName($SelectedEntry.Target.Path)
    if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
    $Results.Add($SelectedEntry.Target.Path)
  }
  if ($ArchivePaths.Count -eq 1 -and $SelectedEntries.Count -gt 0) {
    $Cabinet = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($ArchivePaths[0])
    foreach ($Index in 0..($SelectedEntries.Count - 1)) {
      $Cabinet.UnpackFile($SelectedEntries[$Index].Entry.FullName, $Results[$Index])
    }
  } elseif ($SelectedEntries.Count -gt 0) {
    $SelectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($SelectedEntry in $SelectedEntries) { $null = $SelectedNames.Add($SelectedEntry.Entry.FullName) }
    $Predicate = [Predicate[string]] { param($EntryName) $SelectedNames.Contains($EntryName) }
    $StagingPath = New-TempFolder
    try {
      $Context = [Microsoft.Deployment.Compression.ArchiveFileStreamContext]::new($ArchivePaths, $StagingPath, $null)
      $Engine = [Microsoft.Deployment.Compression.Cab.CabEngine]::new()
      try { $Engine.Unpack($Context, $Predicate) } finally { $Engine.Dispose() }
      foreach ($SelectedEntry in $SelectedEntries) {
        $StagedPath = Resolve-SafeExtractionPath -DestinationPath $StagingPath -RelativePath $SelectedEntry.Entry.FullName
        if (-not (Test-Path -LiteralPath $StagedPath -PathType Leaf)) { throw "The cabinet entry was not extracted: $($SelectedEntry.Entry.FullName)" }
        [IO.File]::Copy($StagedPath, $SelectedEntry.Target.Path, $true)
      }
    } finally { Remove-Item -LiteralPath $StagingPath -Recurse -Force -ErrorAction SilentlyContinue }
  }
  return @($Results)
}

Export-ModuleMember -Function Import-CabinetDependency, Get-CabinetEntry, Export-CabinetEntry
