# SPDX-License-Identifier: MIT

# Test files live exactly one directory below Tests. Resolve all implementation paths from this
# support file so moving a suite between domain folders does not change its module imports.
$Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
$Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
$Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))

# Discovery-time helpers are loaded here. Suite-owned BeforeAll blocks repeat the same initialization
# because Pester 6 intentionally separates discovery and execution scopes.
. (Join-Path $PSScriptRoot 'TestFixture.ps1')
