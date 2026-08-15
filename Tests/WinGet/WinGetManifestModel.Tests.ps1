. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeDiscovery {
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Data\YamlSchema.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetManifestSchema.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetManifestModel.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetMatching.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetManifestSerialization.psm1') -Force
}

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
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

  It 'removes InstallerLocale when every installer has the same locale' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.Locale' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{ InstallerLocale = 'en-US' }) -Installers @(
      [ordered]@{ Architecture = 'x86'; InstallerType = 'nullsoft'; InstallerLocale = 'en-US'; InstallerUrl = 'https://example.test/x86.exe'; InstallerSha256 = 'A' * 64 }
      [ordered]@{ Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerLocale = 'en-us'; InstallerUrl = 'https://example.test/x64.exe'; InstallerSha256 = 'B' * 64 }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Test'; PackageName = 'Test Locale'; License = 'MIT'; ShortDescription = 'Test.' })

    $Optimized = Optimize-WinGetManifest -Manifest $Model
    $Documents = ConvertTo-WinGetManifestDocumentSet -Manifest $Model

    $Optimized.InstallerDefaults.Contains('InstallerLocale') | Should -BeFalse
    @($Optimized.Installers | Where-Object { $_.Contains('InstallerLocale') }).Count | Should -Be 0
    $Documents.Installer.Contains('InstallerLocale') | Should -BeFalse
    @($Documents.Installer.Installers | Where-Object { $_.Contains('InstallerLocale') }).Count | Should -Be 0
  }

  It 'retains InstallerLocale when it differentiates installers' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.Locale' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{ Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerLocale = 'en-US'; InstallerUrl = 'https://example.test/en.exe'; InstallerSha256 = 'A' * 64 }
      [ordered]@{ Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerLocale = 'zh-CN'; InstallerUrl = 'https://example.test/zh.exe'; InstallerSha256 = 'B' * 64 }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Test'; PackageName = 'Test Locale'; License = 'MIT'; ShortDescription = 'Test.' })

    $Optimized = Optimize-WinGetManifest -Manifest $Model

    $Optimized.Installers.InstallerLocale | Should -Be @('en-US', 'zh-CN')
  }

  It 'removes redundant ARP identity fields while retaining meaningful evidence' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.Model' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'wix'; InstallerUrl = 'https://example.test/setup.msi'; InstallerSha256 = 'A' * 64
        ProductCode = '{PRODUCT-CODE}'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName = 'Test Model 1.0.0'; Publisher = 'Test, Inc.'; ProductCode = '{product-code}'; UpgradeCode = '{UPGRADE-CODE}'; InstallerType = 'wix'
          })
      }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Test Inc'; PackageName = 'Test Model'; License = 'MIT'; ShortDescription = 'Test.' })

    $Optimized = Optimize-WinGetManifest -Manifest $Model
    $Entry = $Optimized.Installers[0].AppsAndFeaturesEntries[0]

    $Entry.Contains('ProductCode') | Should -BeFalse
    $Entry.Contains('DisplayName') | Should -BeFalse
    $Entry.Contains('Publisher') | Should -BeFalse
    $Entry.Contains('InstallerType') | Should -BeFalse
    $Entry.UpgradeCode | Should -Be '{UPGRADE-CODE}'
  }

  It 'removes only an AppsAndFeaturesEntries InstallerType that restates the effective type' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.Types' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'zip'; NestedInstallerType = 'wix'; InstallerUrl = 'https://example.test/setup.zip'; InstallerSha256 = 'A' * 64
        AppsAndFeaturesEntries = @([ordered]@{ InstallerType = 'wix'; ProductCode = '{DIFFERENT-PRODUCT}'; UpgradeCode = '{UPGRADE}' })
      }
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'wix'; InstallerUrl = 'https://example.test/custom.msi'; InstallerSha256 = 'B' * 64
        AppsAndFeaturesEntries = @([ordered]@{ InstallerType = 'exe'; ProductCode = 'Custom.Entry' })
      }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Test'; PackageName = 'Test Types'; License = 'MIT'; ShortDescription = 'Test.' })

    $Optimized = Optimize-WinGetManifest -Manifest $Model

    $Optimized.Installers[0].AppsAndFeaturesEntries[0].Contains('InstallerType') | Should -BeFalse
    $Optimized.Installers[0].AppsAndFeaturesEntries[0].ProductCode | Should -Be '{DIFFERENT-PRODUCT}'
    $Optimized.Installers[1].AppsAndFeaturesEntries[0].InstallerType | Should -Be 'exe'
  }

  It 'removes redundant ARP name and publisher while retaining a different ProductCode' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.CustomARP' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'wix'; InstallerUrl = 'https://example.test/setup.msi'; InstallerSha256 = 'A' * 64
        ProductCode = '{MSI-PRODUCT}'
        AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Default App 1.0.0'; Publisher = 'Default Company, Inc.'; ProductCode = 'Custom.Entry' })
      }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Default Company'; PackageName = 'Default App'; License = 'MIT'; ShortDescription = 'Test.' })

    $Optimized = Optimize-WinGetManifest -Manifest $Model
    $Entry = $Optimized.Installers[0].AppsAndFeaturesEntries[0]

    $Entry.ProductCode | Should -Be 'Custom.Entry'
    $Entry.Contains('DisplayName') | Should -BeFalse
    $Entry.Contains('Publisher') | Should -BeFalse
  }

  It 'removes ARP names and publishers represented by an additional locale manifest' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.Localized' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64
        ProductCode = 'Test.Localized'
        AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Localized App'; Publisher = 'Localized Company'; ProductCode = 'Test.Localized' })
      }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Default Company'; PackageName = 'Default App'; License = 'MIT'; ShortDescription = 'Test.' }) -Localizations @(
      [ordered]@{ PackageLocale = 'fr-FR'; Publisher = 'Localized Company'; PackageName = 'Localized App' }
    )

    $Optimized = Optimize-WinGetManifest -Manifest $Model

    $Optimized.Installers[0].Contains('AppsAndFeaturesEntries') | Should -BeFalse
  }

  It 'retains ARP identity fields absent from every locale manifest' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.Unlocalized' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64
        ProductCode = 'Test.Unlocalized'
        AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Unauthored App'; Publisher = 'Unauthored Company'; ProductCode = 'Test.Unlocalized' })
      }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Default Company'; PackageName = 'Default App'; License = 'MIT'; ShortDescription = 'Test.' }) -Localizations @(
      [ordered]@{ PackageLocale = 'fr-FR'; Publisher = 'Localized Company'; PackageName = 'Localized App' }
    )

    $Optimized = Optimize-WinGetManifest -Manifest $Model
    $Entry = $Optimized.Installers[0].AppsAndFeaturesEntries[0]

    $Entry.Contains('ProductCode') | Should -BeFalse
    $Entry.DisplayName | Should -Be 'Unauthored App'
    $Entry.Publisher | Should -Be 'Unauthored Company'
  }

  It 'removes a redundant versioned DisplayName when the ARP publisher is inherited' {
    $Model = New-WinGetManifestModel -PackageIdentifier 'JGraph.Draw' -PackageVersion '31.0.2' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerUrl = 'https://example.test/draw.exe'; InstallerSha256 = 'A' * 64
        ProductCode = 'draw-product'
        AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'draw.io 31.0.2'; ProductCode = 'draw-product' })
      }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'JGraph Ltd'; PackageName = 'draw.io'; License = 'Apache-2.0'; ShortDescription = 'Diagramming.' })

    $Optimized = Optimize-WinGetManifest -Manifest $Model

    $Optimized.Installers[0].Contains('AppsAndFeaturesEntries') | Should -BeFalse
  }

  It 'does not simplify multiple or differently keyed AppsAndFeaturesEntries' {
    $Entries = @(
      [ordered]@{ DisplayName = 'Test Model'; ProductCode = 'Different.Product' }
      [ordered]@{ DisplayName = 'Test Model Legacy'; ProductCode = 'Legacy.Product' }
    )
    $Model = New-WinGetManifestModel -PackageIdentifier 'Test.Model' -PackageVersion '1.0.0' -ManifestVersion '1.12.0' -InstallerDefaults ([ordered]@{}) -Installers @(
      [ordered]@{
        Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64
        ProductCode = 'Test.Product'; AppsAndFeaturesEntries = $Entries
      }
    ) -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Test'; PackageName = 'Test Model'; License = 'MIT'; ShortDescription = 'Test.' })

    $Optimized = Optimize-WinGetManifest -Manifest $Model

    (ConvertTo-Json $Optimized.Installers[0].AppsAndFeaturesEntries -Compress) | Should -BeExactly (ConvertTo-Json $Entries -Compress)
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
