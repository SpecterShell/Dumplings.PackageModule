# SPDX-License-Identifier: MIT
# This shared source is kept byte-identical in PackageModule and InstallerParsers.

function Use-InstallerRuntimeLoadLock {
  <#
  .SYNOPSIS
    Serialize process-wide Add-Type and assembly-load operations
  .PARAMETER ScriptBlock
    The loader operation to run while holding the named mutex
  #>
  param (
    [Parameter(Mandatory)]
    [scriptblock]$ScriptBlock
  )

  # Type visibility is process-wide while PowerShell module state is runspace-local. The named
  # mutex closes the race where parallel task runspaces both pass a PSTypeName check before one
  # of their Add-Type calls publishes the shared types.
  $Mutex = [System.Threading.Mutex]::new($false, 'Local\Dumplings-InstallerInfrastructure-Loader')
  $Acquired = $false
  try {
    try {
      $Acquired = $Mutex.WaitOne([TimeSpan]::FromMinutes(2))
    } catch [System.Threading.AbandonedMutexException] {
      $Acquired = $true
    }
    if (-not $Acquired) { throw 'Timed out waiting for the shared installer infrastructure loader' }
    & $ScriptBlock
  } finally {
    if ($Acquired) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}

function Import-InstallerInfrastructure {
  <#
  .SYNOPSIS
    Compile and load the shared installer infrastructure once
  .NOTES
    The source remains visible and independently consumable in each submodule.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerInfrastructure.BinaryIO').Type) { return }

  Use-InstallerRuntimeLoadLock {
    # Recheck after entering the critical section because another runspace may have loaded the
    # process-wide types while this caller was waiting.
    if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerInfrastructure.BinaryIO').Type) { return }
    $AssetRoot = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets'
    $SourceRoot = Join-Path -Path $AssetRoot -ChildPath 'Source' -AdditionalChildPath 'InstallerInfrastructure'
    if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
      # InstallerParsers retains the original independently consumable layout.
      $SourceRoot = Join-Path -Path $AssetRoot -ChildPath 'InstallerInfrastructure'
    }
    $SourceFiles = @(Get-ChildItem -LiteralPath $SourceRoot -Filter '*.cs' -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
    if ($SourceFiles.Count -eq 0) { throw "The installer infrastructure source is missing: $SourceRoot" }
    Add-Type -Path $SourceFiles -ErrorAction Stop
  }
}

function Import-InstallerManagedAssembly {
  <#
  .SYNOPSIS
    Load a pinned managed assembly from the submodule asset directory once
  .PARAMETER Name
    File name of the managed assembly below the asset root.
  .PARAMETER TypeName
    Fully qualified type used to detect whether the assembly is already loaded.
  .PARAMETER AssetRoot
    Optional explicit asset directory. Cross-submodule callers should supply this because the
    globally visible mirrored loader may belong to either independently consumable submodule.
  #>
  [OutputType([System.Reflection.Assembly])]
  param (
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$TypeName,
    [string]$AssetRoot
  )

  $LoadedType = [System.Management.Automation.PSTypeName]$TypeName
  if ($LoadedType.Type) { return $LoadedType.Type.Assembly }
  $AssemblyName = $Name
  $SimpleAssemblyName = [IO.Path]::GetFileNameWithoutExtension($AssemblyName)
  Use-InstallerRuntimeLoadLock {
    $LoadedType = [System.Management.Automation.PSTypeName]$TypeName
    if ($LoadedType.Type) { return $LoadedType.Type.Assembly }

    # Another module can load a compatible DTF/SharpCompress dependency from a
    # different path before PowerShell has cached its public types. Reuse that
    # assembly by identity rather than asking Add-Type to load the same strong
    # name into the default AssemblyLoadContext a second time.
    $LoadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -ceq $SimpleAssemblyName } | Select-Object -First 1
    if ($LoadedAssembly) {
      if (-not $LoadedAssembly.GetType($TypeName, $false, $false)) {
        throw "Assembly '$SimpleAssemblyName' is already loaded from '$($LoadedAssembly.Location)' but does not expose required type '$TypeName'. Run the incompatible module in a separate PowerShell process."
      }
      return $LoadedAssembly
    }
    $ResolvedAssetRoot = if ([string]::IsNullOrWhiteSpace($AssetRoot)) {
      Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets'
    } else {
      [IO.Path]::GetFullPath($AssetRoot)
    }
    $AssemblyPath = Join-Path -Path $ResolvedAssetRoot -ChildPath 'Assemblies' -AdditionalChildPath $AssemblyName
    if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) {
      # InstallerParsers retains the original independently consumable layout.
      $AssemblyPath = Join-Path -Path $ResolvedAssetRoot -ChildPath $AssemblyName
    }
    if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) { throw "The managed dependency is missing: $AssemblyPath" }
    Add-Type -Path $AssemblyPath -PassThru -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Assembly
  }
}

function Import-InstallerManagedSource {
  <#
  .SYNOPSIS
    Compile a related set of managed source files exactly once per process
  .PARAMETER Path
    Source files compiled together. Paths are resolved before Add-Type because the .NET
    process current directory can differ from PowerShell's provider location.
  .PARAMETER TypeName
    A fully qualified type published by the source set and used as the load sentinel.
  .OUTPUTS
    The assembly containing TypeName.
  #>
  [OutputType([System.Reflection.Assembly])]
  param (
    [Parameter(Mandatory)][string[]]$Path,
    [Parameter(Mandatory)][string]$TypeName
  )

  $LoadedType = [System.Management.Automation.PSTypeName]$TypeName
  if ($LoadedType.Type) { return $LoadedType.Type.Assembly }

  # Resolve the complete source set before taking the process-wide compiler lock. This keeps
  # slow filesystem failures outside the critical section and gives Add-Type absolute paths.
  $SourceFiles = [Collections.Generic.List[string]]::new()
  foreach ($SourcePath in $Path) {
    $SourceFiles.Add((Get-Item -LiteralPath $SourcePath -Force -ErrorAction Stop).FullName)
  }
  if ($SourceFiles.Count -eq 0) { throw 'At least one managed source file is required.' }

  return Use-InstallerRuntimeLoadLock {
    # A competing runspace may have compiled this source set while this caller waited.
    $LoadedType = [System.Management.Automation.PSTypeName]$TypeName
    if ($LoadedType.Type) { return $LoadedType.Type.Assembly }
    Add-Type -Path @($SourceFiles) -ErrorAction Stop
    $LoadedType = [System.Management.Automation.PSTypeName]$TypeName
    if (-not $LoadedType.Type) { throw "Managed source compilation did not publish the expected type '$TypeName'." }
    return $LoadedType.Type.Assembly
  }
}

function Import-InstallerArchiveDependency {
  <#
  .SYNOPSIS
    Load the pinned ZstdSharp and SharpCompress assemblies in dependency order
  #>
  if (([System.Management.Automation.PSTypeName]'SharpCompress.Archives.ArchiveFactory').Type) { return }
  $null = Import-InstallerManagedAssembly -Name 'ZstdSharp.dll' -TypeName 'ZstdSharp.Decompressor'
  $null = Import-InstallerManagedAssembly -Name 'SharpCompress.dll' -TypeName 'SharpCompress.Archives.ArchiveFactory'
}

Export-ModuleMember -Function Use-InstallerRuntimeLoadLock, Import-InstallerInfrastructure, Import-InstallerManagedAssembly, Import-InstallerManagedSource, Import-InstallerArchiveDependency
