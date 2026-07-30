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
  .PARAMETER MaximumEntries
    The maximum number of catalog entries accepted across the cabinet set
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string[]]$Path,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536
  )

  Import-CabinetDependency
  $ArchivePaths = [Collections.Generic.List[string]]::new()
  foreach ($ArchivePath in $Path) { $ArchivePaths.Add((Get-Item -LiteralPath $ArchivePath -Force).FullName) }
  if ($ArchivePaths.Count -eq 1) {
    $Cabinet = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($ArchivePaths[0])
    $Entries = @($Cabinet.GetFiles())
  } else {
    $Context = [Microsoft.Deployment.Compression.ArchiveFileStreamContext]::new($ArchivePaths, $null, $null)
    $Engine = [Microsoft.Deployment.Compression.Cab.CabEngine]::new()
    try { $Entries = @($Engine.GetFileInfo($Context, $null)) } finally { $Engine.Dispose() }
  }
  if ($Entries.Count -gt $MaximumEntries) { throw 'The cabinet catalog exceeds the configured entry limit.' }
  foreach ($Entry in $Entries) {
    # Cabinet catalogs may store media-root paths beginning with a separator. Preserve the
    # raw source name for decoder lookup while exposing a safe extraction-relative name.
    # CabFileInfo.FullName may be a synthetic "cabinet-path\entry" filesystem
    # path. Rebuild the authored lookup identity from its catalog path and name;
    # PackageForTheWeb root entries intentionally retain a leading separator.
    $CatalogPath = [string]$Entry.Path
    $SourceName = if ([string]::IsNullOrEmpty($CatalogPath)) {
      [string]$Entry.Name
    } elseif ($CatalogPath.EndsWith('\') -or $CatalogPath.EndsWith('/')) {
      $CatalogPath + [string]$Entry.Name
    } else {
      $CatalogPath + '\' + [string]$Entry.Name
    }
    [pscustomobject]@{
      FullName   = $SourceName.Replace('/', '\').TrimStart('\')
      SourceName = $SourceName
      Length     = [long]$Entry.Length
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
  .PARAMETER MaximumEntries
    The maximum number of catalog entries accepted before selection
  .PARAMETER ReservedPath
    Optional case-insensitive target set shared with an outer extraction operation
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][string[]]$Path,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296,
    [Collections.Generic.ISet[string]]$ReservedPath
  )

  Import-CabinetDependency
  $ArchivePaths = [Collections.Generic.List[string]]::new()
  foreach ($ArchivePath in $Path) { $ArchivePaths.Add((Resolve-InstallerFileSystemPath -Path $ArchivePath -PathType Leaf)) }
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $Entries = @(Get-CabinetEntry -Path $ArchivePaths -MaximumEntries $MaximumEntries | Where-Object { Test-ExtractionPattern -Path $_.FullName -Pattern $Name })
  # Preserve an empty caller-owned set so outer extractors observe every path
  # reserved by this cabinet operation. Truthiness would replace an empty set.
  $ReservedPaths = $null -ne $ReservedPath ? $ReservedPath : [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
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
    # DTF's one-file API cannot address a cabinet entry whose authored path starts with a
    # separator. Unpack a source-to-staging map, then copy to collision-resolved targets.
    $StagingPath = New-TempFolder
    try {
      $FileMap = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Index in 0..($SelectedEntries.Count - 1)) {
        $FileMap.Add([string]$SelectedEntries[$Index].Entry.SourceName, ('entry-{0:D8}.bin' -f $Index))
      }
      $Cabinet.UnpackFileSet($FileMap, $StagingPath)
      foreach ($Index in 0..($SelectedEntries.Count - 1)) {
        $StagedPath = Join-Path $StagingPath ('entry-{0:D8}.bin' -f $Index)
        if (-not (Test-Path -LiteralPath $StagedPath -PathType Leaf)) { throw "The cabinet entry was not extracted: $($SelectedEntries[$Index].Entry.FullName)" }
        [IO.File]::Copy($StagedPath, $Results[$Index], $true)
      }
    } finally { Remove-Item -LiteralPath $StagingPath -Recurse -Force -ErrorAction SilentlyContinue }
  } elseif ($SelectedEntries.Count -gt 0) {
    $SelectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($SelectedEntry in $SelectedEntries) { $null = $SelectedNames.Add($SelectedEntry.Entry.SourceName) }
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
