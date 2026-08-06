# SPDX-License-Identifier: Apache-2.0

function Import-CabinetDependency {
  <#
  .SYNOPSIS
    Load the bundled Microsoft cabinet reader
  #>
  if (-not ([Management.Automation.PSTypeName]'Microsoft.Deployment.Compression.Cab.CabInfo').Type) {
    foreach ($AssemblyName in @('Microsoft.Deployment.Compression.dll', 'Microsoft.Deployment.Compression.Cab.dll')) {
      $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Assemblies', $AssemblyName
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

function Export-CabinetSelection {
  <#
  .SYNOPSIS
    Export an already validated mapping of cabinet source entries to output files
  .DESCRIPTION
    This lower-level helper performs the mechanical cabinet decode for callers
    that have already selected entries and resolved collision-safe destinations.
    Repeated references to one cabinet source entry are decoded once and copied
    to each requested destination.
  .PARAMETER Path
    The resolved path to one cabinet file.
  .PARAMETER Selection
    Objects containing SourceName, DestinationPath, and expected Length values.
    DestinationPath must already have passed the caller's safe-path and collision
    policy; this helper does not reserve or rename outputs.
  .PARAMETER MaximumEntries
    Maximum number of logical output selections accepted.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate bytes copied to logical outputs. Repeated aliases are
    charged separately because they create separate files.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Selection,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )

  Import-CabinetDependency
  $CabinetPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  if ($Selection.Count -gt $MaximumEntries) { throw 'The selected cabinet entries exceed the configured entry limit.' }
  if ($Selection.Count -eq 0) { return @() }

  $NormalizedSelection = [Collections.Generic.List[object]]::new($Selection.Count)
  [long]$TotalLength = 0
  foreach ($Item in $Selection) {
    $SourceName = [string]$Item.SourceName
    $DestinationPath = [string]$Item.DestinationPath
    if ([string]::IsNullOrWhiteSpace($SourceName)) { throw 'A selected cabinet entry has no source name.' }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { throw "The selected cabinet entry '$SourceName' has no destination path." }
    [long]$Length = $Item.Length
    if ($Length -lt 0) { throw "The selected cabinet entry '$SourceName' has an invalid length." }
    if ($Length -gt $MaximumExpandedBytes - $TotalLength) { throw 'The selected cabinet entries exceed the configured output limit.' }
    $TotalLength += $Length
    $NormalizedSelection.Add([pscustomobject]@{
        SourceName      = $SourceName
        DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
        Length          = $Length
      })
  }

  $StagingPath = New-TempFolder
  try {
    # DTF accepts a source-to-relative-output dictionary. Assign opaque staging
    # names so cabinet paths can never escape the temporary extraction root.
    $FileMap = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Item in $NormalizedSelection) {
      if (-not $FileMap.ContainsKey($Item.SourceName)) {
        $FileMap.Add($Item.SourceName, ('entry-{0:D8}.bin' -f $FileMap.Count))
      }
    }
    $Cabinet = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($CabinetPath)
    $Cabinet.UnpackFileSet($FileMap, $StagingPath)

    $Results = [Collections.Generic.List[string]]::new($NormalizedSelection.Count)
    foreach ($Item in $NormalizedSelection) {
      $StagedPath = Join-Path $StagingPath $FileMap[$Item.SourceName]
      if (-not (Test-Path -LiteralPath $StagedPath -PathType Leaf)) { throw "The cabinet entry was not extracted: $($Item.SourceName)" }
      $StagedFile = Get-Item -LiteralPath $StagedPath -Force
      if ($StagedFile.Length -ne $Item.Length) { throw "The extracted cabinet entry length does not match its catalog: $($Item.SourceName)" }
      $Parent = [IO.Path]::GetDirectoryName($Item.DestinationPath)
      if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
      [IO.File]::Copy($StagedFile.FullName, $Item.DestinationPath, $true)
      $Results.Add($Item.DestinationPath)
    }
    return $Results.ToArray()
  } finally {
    Remove-Item -LiteralPath $StagingPath -Recurse -Force -ErrorAction SilentlyContinue
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
    $MappedSelection = @($SelectedEntries | ForEach-Object {
        [pscustomobject]@{
          SourceName      = $_.Entry.SourceName
          DestinationPath = $_.Target.Path
          Length          = $_.Entry.Length
        }
      })
    $null = Export-CabinetSelection -Path $ArchivePaths[0] -Selection $MappedSelection `
      -MaximumEntries $MaximumEntries -MaximumExpandedBytes $MaximumExpandedBytes
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

Export-ModuleMember -Function Import-CabinetDependency, Get-CabinetEntry, Export-CabinetSelection, Export-CabinetEntry
