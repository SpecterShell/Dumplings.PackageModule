BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\YamlSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestModel.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestSerialization.psm1') -Force
}

BeforeAll {
  function New-TestWinGetSingleton {
    return [ordered]@{
      PackageIdentifier = 'Test.Model'; PackageVersion = '1.0.0'; PackageLocale = 'en-US'
      Channel = 'stable'; Moniker = 'test-model'
      Publisher = 'Test'; PackageName = 'Test Model'; License = 'MIT'; ShortDescription = 'Test model.'
      InstallerType = 'wix'
      InstallerSwitches = [ordered]@{ Custom = 'ROOT=1' }
      Dependencies = [ordered]@{ PackageDependencies = @([ordered]@{ PackageIdentifier = 'Test.Dependency'; MinimumVersion = '2.0.0' }) }
      Installers = @([ordered]@{
          Architecture = 'x64'; InstallerUrl = 'https://example.test/setup.msi'; InstallerSha256 = 'A' * 64
          InstallerSwitches = [ordered]@{ InstallLocation = 'INSTALLDIR="<INSTALLPATH>"' }
        })
      ManifestType = 'singleton'; ManifestVersion = '1.12.0'
    }
  }
}

Describe 'WinGet logical manifest model' {
  It 'normalizes singleton input to multi-file documents with effective authored values' {
    $Model = ConvertFrom-WinGetManifestYaml -Content (ConvertTo-Yaml (New-TestWinGetSingleton))
    $Documents = ConvertTo-WinGetManifestDocumentSet -Manifest $Model

    $Model.SourceFormat | Should -Be Singleton
    $Model.Installers[0].InstallerSwitches.Custom | Should -Be 'ROOT=1'
    $Model.Installers[0].InstallerSwitches.InstallLocation | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
    $Documents.Version.ManifestType | Should -Be version
    $Documents.Version.Contains('Channel') | Should -BeFalse
    $Documents.Version.Contains('Moniker') | Should -BeFalse
    $Documents.Installer.ManifestType | Should -Be installer
    $Documents.Installer.Channel | Should -Be stable
    $Documents.DefaultLocale.ManifestType | Should -Be defaultLocale
    $Documents.DefaultLocale.Moniker | Should -Be test-model
    $Model.InstallerDefaults.Contains('Channel') | Should -BeFalse
    $Model.DefaultLocalization.Contains('Moniker') | Should -BeFalse
  }

  It 'produces the same logical contract from singleton and equivalent multi-file input' {
    $SingletonModel = ConvertFrom-WinGetManifestYaml -Content (ConvertTo-Yaml (New-TestWinGetSingleton))
    $Bundle = ConvertTo-WinGetManifestYaml -Manifest $SingletonModel
    $MultiFileModel = ConvertFrom-WinGetManifestYaml -Content $Bundle

    $SingletonModel.PackageIdentifier | Should -Be $MultiFileModel.PackageIdentifier
    $SingletonModel.PackageVersion | Should -Be $MultiFileModel.PackageVersion
    $MultiFileModel.Channel | Should -Be stable
    $MultiFileModel.Moniker | Should -Be test-model
    (ConvertTo-Json $SingletonModel.Installers -Depth 100 -Compress) | Should -BeExactly (ConvertTo-Json $MultiFileModel.Installers -Depth 100 -Compress)
    (ConvertTo-Json $SingletonModel.DefaultLocalization -Depth 100 -Compress) | Should -BeExactly (ConvertTo-Json $MultiFileModel.DefaultLocalization -Depth 100 -Compress)
  }

  It 'preserves one-item dependency arrays and compacts dictionary atoms recursively' {
    $Model = ConvertFrom-WinGetMergedManifest -Manifest (New-TestWinGetSingleton) -SourceFormat Singleton
    $Merged = ConvertTo-WinGetMergedManifest -Manifest $Model

    @($Merged.Dependencies.PackageDependencies).Count | Should -Be 1
    $Merged.Dependencies.PackageDependencies[0].PackageIdentifier | Should -Be 'Test.Dependency'
    $Merged.InstallerSwitches.Custom | Should -Be 'ROOT=1'
    $Merged.InstallerSwitches.InstallLocation | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
  }

  It 'does not mutate the source model during projection or serialization' {
    $Model = ConvertFrom-WinGetMergedManifest -Manifest (New-TestWinGetSingleton) -SourceFormat Singleton
    $Before = ConvertTo-Json $Model -Depth 100 -Compress
    $null = ConvertTo-WinGetMergedManifest -Manifest $Model
    $null = ConvertTo-WinGetManifestYaml -Manifest $Model
    (ConvertTo-Json $Model -Depth 100 -Compress) | Should -BeExactly $Before
  }

  It 'keeps runtime defaults out of the authored model' {
    $Model = ConvertFrom-WinGetMergedManifest -Manifest (New-TestWinGetSingleton) -SourceFormat Singleton
    $Model.Installers[0].InstallerSwitches.Contains('Silent') | Should -BeFalse
    $Model.Installers[0].Contains('ExpectedReturnCodes') | Should -BeFalse
  }

  It 'sorts only Tags during individual manifest formatting' {
    $Locale = [ordered]@{
      PackageIdentifier = 'Test.Model'; PackageVersion = '1.0.0'; PackageLocale = 'en-US'
      Publisher = 'Test'; PackageName = 'Test'; License = 'MIT'; ShortDescription = 'Test.'
      Tags = @('z', 'a', 'z'); Agreements = @([ordered]@{ AgreementLabel = 'Second' }, [ordered]@{ AgreementLabel = 'First' })
      ManifestType = 'defaultLocale'; ManifestVersion = '1.12.0'
    }
    $Formatted = Format-WinGetManifest -Manifest $Locale
    $Formatted.Tags | Should -Be @('a', 'z')
    $Formatted.Agreements.AgreementLabel | Should -Be @('Second', 'First')
  }
}
