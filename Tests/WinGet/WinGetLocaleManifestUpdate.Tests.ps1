. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Index.ps1') -Force

  function New-LocaleManifest {
    param ([string]$Copyright = 'Copyright 2024 The Test Authors. All rights reserved.')

    [ordered]@{
      PackageIdentifier = 'Test.Package'
      PackageVersion    = '1.0.0'
      PackageLocale     = 'zh-CN'
      Publisher         = 'Test Publisher'
      PackageName       = 'Test Package'
      License           = 'Test License'
      ShortDescription  = 'Test package'
      Copyright         = $Copyright
      ReleaseNotes      = 'Existing release notes'
      ManifestType      = 'locale'
      ManifestVersion   = '1.12.0'
    }
  }
}

Describe 'Update-WinGetLocaleManifest' -Tag Unit {
  # The locale update is module-internal, so each case passes its manifest into the module scope
  # instead of relying on an exported command.
  It 'cleans up the release notes and refreshes the copyright year by default' {
    $Result = @(InModuleScope WinGetManifestUpdate -Parameters @{ Manifest = (New-LocaleManifest) } {
        Update-WinGetLocaleManifest -OldLocaleManifests @($Manifest) -PackageVersion '1.0.0'
      })

    $Result[0].Contains('ReleaseNotes') | Should -BeFalse
    $Result[0].Copyright | Should -Be "Copyright $((Get-Date).Year) The Test Authors. All rights reserved."
  }

  It 'refreshes only the newest year of a copyright range' {
    $Result = @(InModuleScope WinGetManifestUpdate -Parameters @{ Manifest = (New-LocaleManifest -Copyright 'Copyright 2019, 2023 The Test Authors. All rights reserved.') } {
        Update-WinGetLocaleManifest -OldLocaleManifests @($Manifest) -PackageVersion '1.0.0'
      })

    $Result[0].Copyright | Should -Be "Copyright 2019, $((Get-Date).Year) The Test Authors. All rights reserved."
  }

  It 'keeps the release notes of an existing version when the authored metadata is preserved' {
    $Result = @(InModuleScope WinGetManifestUpdate -Parameters @{ Manifest = (New-LocaleManifest) } {
        Update-WinGetLocaleManifest -OldLocaleManifests @($Manifest) -PackageVersion '1.0.0' -PreserveAuthoredMetadata
      })

    $Result[0].ReleaseNotes | Should -Be 'Existing release notes'
  }

  It 'keeps the copyright year of an existing version when the authored metadata is preserved' {
    $Result = @(InModuleScope WinGetManifestUpdate -Parameters @{ Manifest = (New-LocaleManifest) } {
        Update-WinGetLocaleManifest -OldLocaleManifests @($Manifest) -PackageVersion '1.0.0' -PreserveAuthoredMetadata
      })

    $Result[0].Copyright | Should -Be 'Copyright 2024 The Test Authors. All rights reserved.'
  }
}
