# SPDX-License-Identifier: MIT
# This shared source is kept byte-identical in PackageModule and InstallerParsers.

function Import-InstallerInfrastructure {
  <#
  .SYNOPSIS
    Compile and load the shared installer infrastructure once
  .NOTES
    The source remains visible and independently consumable in each submodule.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerInfrastructure.BinaryIO').Type) { return }

  $SourceRoot = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'InstallerInfrastructure'
  $SourceFiles = @(Get-ChildItem -LiteralPath $SourceRoot -Filter '*.cs' -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
  if ($SourceFiles.Count -eq 0) { throw "The installer infrastructure source is missing: $SourceRoot" }
  Add-Type -Path $SourceFiles -ErrorAction Stop
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
  $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', $Name
  if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) { throw "The managed dependency is missing: $AssemblyPath" }
  return Add-Type -Path $AssemblyPath -PassThru -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Assembly
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
