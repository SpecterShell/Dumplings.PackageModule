. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\WinGetManifestTestSetup.ps1')

Describe 'Format-WinGetManifest' -Tag Unit {
  It 'moves only common installer values to the manifest level and preserves overrides' {
    $Manifest = [ordered]@{
      PackageIdentifier = 'Example.Package'
      PackageVersion    = '1.0.0'
      InstallerType     = 'zip'
      Installers        = @(
        [ordered]@{
          Architecture         = 'x86'
          NestedInstallerType  = 'wix'
          Scope                = 'machine'
          InstallerSwitches    = [ordered]@{ InstallLocation = 'INSTALLLOCATION="<INSTALLPATH>"' }
          NestedInstallerFiles = @([ordered]@{ RelativeFilePath = 'x86.msi' })
          InstallerUrl         = 'https://example.test/x86.zip'
          InstallerSha256      = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
          ProductCode          = '{11111111-1111-1111-1111-111111111111}'
        }
        [ordered]@{
          Architecture         = 'x64'
          NestedInstallerType  = 'wix'
          Scope                = 'machine'
          InstallerSwitches    = [ordered]@{ InstallLocation = 'INSTALLLOCATION="<INSTALLPATH>"' }
          NestedInstallerFiles = @([ordered]@{ RelativeFilePath = 'x64.msi' })
          InstallerUrl         = 'https://example.test/x64.zip'
          InstallerSha256      = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
          ProductCode          = '{22222222-2222-2222-2222-222222222222}'
        }
      )
      ManifestType      = 'installer'
      ManifestVersion   = '1.12.0'
    }

    $Result = Format-WinGetManifest -Manifest $Manifest

    $Result.NestedInstallerType | Should -Be 'wix'
    $Result.Scope | Should -Be 'machine'
    $Result.InstallerSwitches.InstallLocation | Should -Be 'INSTALLLOCATION="<INSTALLPATH>"'
    $Result.Installers[0].Contains('Scope') | Should -BeFalse
    $Result.Installers[0].Contains('InstallerSwitches') | Should -BeFalse
    $Result.Installers[0].ProductCode | Should -Be '{11111111-1111-1111-1111-111111111111}'
    $Result.Installers[1].ProductCode | Should -Be '{22222222-2222-2222-2222-222222222222}'
    $Manifest.Installers[0].Contains('Scope') | Should -BeTrue
  }

  It 'does not add unsupported architecture metadata or normalize locale values' {
    $Manifest = [ordered]@{
      PackageIdentifier = 'Example.Package'
      PackageVersion    = '1.0.0'
      PackageLocale     = 'en-US'
      Publisher         = 'Example Publisher'
      PackageName       = 'Example Package'
      License           = 'Proprietary'
      ShortDescription  = 'An example package.'
      Tags              = @('second-tag', 'first-tag')
      ManifestType      = 'defaultLocale'
      ManifestVersion   = '1.12.0'
    }

    $Result = Format-WinGetManifest -Manifest $Manifest

    $Result.Contains('UnsupportedOSArchitectures') | Should -BeFalse
    @($Result.Tags) | Should -Be @('first-tag', 'second-tag')
    $Manifest.Tags | Should -Be @('second-tag', 'first-tag')
  }

  It 'preserves authored fields that semantic validation may reject' {
    $Manifest = [ordered]@{
      PackageIdentifier = 'Example.Invalid'
      PackageVersion    = '1.0.0'
      InstallerType     = 'msix'
      ProductCode       = 'Authored.Invalid.ProductCode'
      Installers        = @([ordered]@{
          Architecture    = 'x64'
          InstallerUrl    = 'https://example.test/package.msix'
          InstallerSha256 = 'A' * 64
        })
      ManifestType      = 'installer'
      ManifestVersion   = '1.12.0'
    }

    $Result = Format-WinGetManifest -Manifest $Manifest

    $Result.ProductCode | Should -Be 'Authored.Invalid.ProductCode'
  }

  It 'keeps isolated formatting non-destructive for authored elevation fields' {
    $Manifest = [ordered]@{
      PackageIdentifier = 'Example.Package'; PackageVersion = '1.0.0'
      InstallerType = 'wix'; ElevationRequirement = 'elevationRequired'
      Installers = @([ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/app.msi'; InstallerSha256 = 'A' * 64 })
      ManifestType = 'installer'; ManifestVersion = '1.12.0'
    }
    (Format-WinGetManifest -Manifest $Manifest).ElevationRequirement | Should -Be elevationRequired
  }
}

Describe 'MSI elevation cleanup during manifest updates' -Tag Unit {
  It 'removes the field even when installer analysis is skipped: <_>' -ForEach @('msi', 'wix') {
    Mock Invoke-WinGetInstallerDownload -ModuleName WinGetManifestUpdate { throw 'A supplied SHA256 should avoid downloading.' }
    $Source = [ordered]@{
      PackageIdentifier = 'Example.Package'; PackageVersion = '1.0.0'; PackageLocale = 'en-US'
      Publisher = 'Example'; PackageName = 'Example Package'; License = 'MIT'; ShortDescription = 'Test package.'
      InstallerType = $_; ElevationRequirement = 'elevationRequired'
      Installers = @([ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/old.msi'; InstallerSha256 = 'A' * 64 })
      ManifestType = 'singleton'; ManifestVersion = '1.12.0'
    }
    $Model = ConvertFrom-WinGetMergedManifest -Manifest $Source
    $Result = Update-WinGetManifest -Manifest $Model -PackageVersion '2.0.0' -InstallerEntries @([ordered]@{ InstallerUrl = 'https://example.test/new.msi'; InstallerSha256 = 'B' * 64 }) -SkipInstallerAnalysis -Logger { $null = $args }
    $Result.Installers[0].Contains('ElevationRequirement') | Should -BeFalse
    $Result.InstallerDefaults.Contains('ElevationRequirement') | Should -BeFalse
    $Model.Installers[0].ElevationRequirement | Should -Be elevationRequired
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName WinGetManifestUpdate -Exactly 0
  }
}
