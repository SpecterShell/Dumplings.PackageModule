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
    $SourceRoot = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'InstallerInfrastructure'
    $SourceFiles = @(Get-ChildItem -LiteralPath $SourceRoot -Filter '*.cs' -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
    if ($SourceFiles.Count -eq 0) { throw "The installer infrastructure source is missing: $SourceRoot" }
    Add-Type -Path $SourceFiles -ErrorAction Stop
  }
}

function Import-InstallerManagedAssembly {
  <#
  .SYNOPSIS
    Load a pinned managed assembly from the submodule asset directory once
  #>
  [OutputType([System.Reflection.Assembly])]
  param (
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$TypeName
  )

  $LoadedType = [System.Management.Automation.PSTypeName]$TypeName
  if ($LoadedType.Type) { return $LoadedType.Type.Assembly }
  $AssemblyName = $Name
  Use-InstallerRuntimeLoadLock {
    $LoadedType = [System.Management.Automation.PSTypeName]$TypeName
    if ($LoadedType.Type) { return $LoadedType.Type.Assembly }
    $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', $AssemblyName
    if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) { throw "The managed dependency is missing: $AssemblyPath" }
    Add-Type -Path $AssemblyPath -PassThru -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Assembly
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

Export-ModuleMember -Function Import-InstallerInfrastructure, Import-InstallerManagedAssembly, Import-InstallerArchiveDependency
