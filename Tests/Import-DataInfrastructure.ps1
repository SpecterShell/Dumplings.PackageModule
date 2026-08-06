# Loads the focused filesystem, data, and web modules required by direct-module tests.
$PackageModuleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $PackageModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
Import-Module (Join-Path $PackageModuleRoot 'Libraries\Data\Text.psm1') -Force
Import-Module (Join-Path $PackageModuleRoot 'Libraries\Data\Format.psm1') -Force
Import-Module (Join-Path $PackageModuleRoot 'Libraries\Data\HTML.psm1') -Force
Import-Module (Join-Path $PackageModuleRoot 'Libraries\Data\Conversion.psm1') -Force
Import-Module (Join-Path $PackageModuleRoot 'Libraries\Data\Object.psm1') -Force
Import-Module (Join-Path $PackageModuleRoot 'Libraries\Networking\Web.psm1') -Force
