BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\YamlSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestModel.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestSerialization.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\InstallerBridge.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\MSI.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\MSIX.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Burn.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\NSIS.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Inno.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\AdvancedInstaller.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\InstallShield.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\ChromiumSetup.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetInstallerAnalyzer.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetDownload.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestUpdate.psm1') -Force
}

Describe 'Get-WinGetInstallerReleaseDate' {
  InModuleScope WinGetManifestUpdate {
    BeforeEach {
      $Script:InstallerPath = Join-Path $TestDrive 'installer.exe'
      $Script:InstallerUrl = 'https://example.test/installer.exe'
      $Script:LogMessages = [System.Collections.Generic.List[object]]::new()
      $Script:Logger = { param($Message, $Level) $Script:LogMessages.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
    }

    It 'reads Last-Modified from the fresh download response headers' {
      $DownloadResult = [pscustomobject]@{
        HttpStatusCode  = 200
        FinalUri        = $null
        ResponseHeaders = "HTTP/1.1 200 OK`r`nContent-Length: 100`r`nLast-Modified: Wed, 15 Jul 2026 08:30:00 GMT`r`n"
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl -DownloadResult $DownloadResult | Should -Be '2026-07-15'
    }

    It 'returns null when the download response has no Last-Modified header' {
      $DownloadResult = [pscustomobject]@{
        HttpStatusCode  = 200
        FinalUri        = $null
        ResponseHeaders = "HTTP/1.1 200 OK`r`nContent-Length: 100`r`n"
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl -DownloadResult $DownloadResult | Should -BeNullOrEmpty
    }

    It 'returns null for an invalid HTTP date' {
      $DownloadResult = [pscustomobject]@{
        HttpStatusCode  = 200
        FinalUri        = $null
        ResponseHeaders = "HTTP/1.1 200 OK`r`nLast-Modified: not-a-date`r`n"
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl -DownloadResult $DownloadResult | Should -BeNullOrEmpty
    }

    It 'falls back to a header request when no download response is available' {
      Mock Get-WebResponseHeader -ModuleName WinGetManifestUpdate {
        $Headers = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
        $Headers['Last-Modified'] = [string[]]@('Tue, 01 Jul 2025 12:00:00 GMT')
        [pscustomobject]@{ Headers = $Headers }
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl | Should -Be '2025-07-01'
    }

    It 'returns null when the header request fails' {
      Mock Get-WebResponseHeader -ModuleName WinGetManifestUpdate { throw 'The remote name could not be resolved' }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl | Should -BeNullOrEmpty
    }

    It 'ignores non-HTTP installer URLs' {
      Get-WinGetInstallerReleaseDate -Uri 'ftp://example.test/installer.exe' | Should -BeNullOrEmpty
    }

    It 'Fills a missing ReleaseDate from the download Last-Modified header' {
      Mock Invoke-WinGetInstallerDownload -ModuleName WinGetManifestUpdate {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1, 2, 3, 4))
        [pscustomobject]@{
          DestinationPath = $DestinationPath
          HttpStatusCode  = 200
          FinalUri        = $null
          ResponseHeaders = "HTTP/1.1 200 OK`r`nLast-Modified: Wed, 15 Jul 2026 08:30:00 GMT`r`n"
        }
      }
      $Installer = [ordered]@{ Architecture = 'x64'; InstallerType = 'exe'; InstallerUrl = $Script:InstallerUrl }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ([ordered]@{}) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{}) -Logger $Script:Logger

      $Result.ReleaseDate | Should -Be '2026-07-15'
    }

    It 'Keeps an existing ReleaseDate instead of the Last-Modified header' {
      Mock Invoke-WinGetInstallerDownload -ModuleName WinGetManifestUpdate {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1, 2, 3, 4))
        [pscustomobject]@{
          DestinationPath = $DestinationPath
          HttpStatusCode  = 200
          FinalUri        = $null
          ResponseHeaders = "HTTP/1.1 200 OK`r`nLast-Modified: Wed, 15 Jul 2026 08:30:00 GMT`r`n"
        }
      }
      $Installer = [ordered]@{ Architecture = 'x64'; InstallerType = 'exe'; InstallerUrl = $Script:InstallerUrl; ReleaseDate = '2020-01-01' }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ([ordered]@{}) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{}) -Logger $Script:Logger

      $Result.ReleaseDate | Should -Be '2020-01-01'
    }
  }
}

Describe 'WinGet installer manifest metadata updates' {
  InModuleScope WinGetManifestUpdate {
    BeforeEach {
      $Script:InstallerPath = Join-Path $TestDrive 'installer.exe'
      [IO.File]::WriteAllBytes($Script:InstallerPath, [byte[]](1, 2, 3, 4))
      $Script:InstallerUrl = 'https://example.test/installer.exe'
      $Script:InstallerFiles = [ordered]@{ $Script:InstallerUrl = $Script:InstallerPath }
      $Script:LogMessages = [System.Collections.Generic.List[object]]::new()
      $Script:Logger = { param($Message, $Level) $Script:LogMessages.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
      Mock Get-WinGetInstallerReleaseDate { return $null }
    }

    It 'Excludes non-authoritative parser fields from manifest metadata' {
      $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject @([pscustomobject]@{
          PackageName    = 'Parser package name'
          Scope          = 'machine'
          Protocols      = @('parser-protocol')
          FileExtensions = @('parserext')
          Dependencies   = [ordered]@{ PackageDependencies = @([ordered]@{ PackageIdentifier = 'Parser.Dependency' }) }
        }) -InstallerType 'exe' -OldInstaller ([ordered]@{})

      $Metadata.Contains('DisplayName') | Should -BeFalse
      foreach ($Field in @('Scope', 'Protocols', 'FileExtensions', 'Dependencies')) {
        $Metadata.Contains($Field) | Should -BeFalse
      }
    }

    It 'Updates NSIS ProductCode and AppsAndFeaturesEntries from one parser result' {
      Mock Get-NSISInfo {
        [pscustomobject]@{
          ProductCode                = 'New.NSIS.Product'
          DisplayName                = 'New NSIS Name'
          DisplayVersion             = '2.0.0'
          Publisher                  = 'New NSIS Publisher'
          WritesAppsAndFeaturesEntry = $true
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'nullsoft'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Old.NSIS.Product'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old NSIS Name'
            DisplayVersion = '1.0.0'
            Publisher      = 'Old NSIS Publisher'
            ProductCode    = 'Old.NSIS.Product'
          })
      }
      $OldInstaller = $Installer | Copy-Object

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'New.NSIS.Product'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New NSIS Name'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '2.0.0'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'New NSIS Publisher'
      $Result.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'New.NSIS.Product'
      Should -Invoke Get-NSISInfo -Exactly 1
    }

    It 'Updates source-derived Inno ProductCode and directory metadata' {
      Mock Get-InnoInfo {
        [pscustomobject]@{
          ProductCode                = '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
          DisplayName                = 'Kiro'
          DisplayVersion             = '3.0.0'
          Publisher                  = 'Amazon Web Services'
          DefaultInstallLocation     = '%LocalAppData%\Programs\Kiro'
          WritesAppsAndFeaturesEntry = $true
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x86'
        InstallerType          = 'inno'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
        InstallationMetadata   = [ordered]@{
          DefaultInstallLocation = '{userpf}\Kiro'
        }
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old Inno Name'
            DisplayVersion = '2.0.0'
            Publisher      = 'Old Inno Publisher'
            ProductCode    = '{{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
          })
      }
      $OldInstaller = $Installer | Copy-Object

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
      $Result.InstallationMetadata.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\Kiro'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Kiro'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '3.0.0'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'Amazon Web Services'
      $Result.AppsAndFeaturesEntries[0].ProductCode | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
      Should -Invoke Get-InnoInfo -Exactly 1
    }

    It 'Preserves existing Inno fields when their values use runtime constants' {
      Mock Get-InnoInfo {
        [pscustomobject]@{
          ProductCode                = $null
          DisplayName                = $null
          DisplayVersion             = $null
          Publisher                  = $null
          DefaultInstallLocation     = $null
          UnresolvedFields           = @('ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'DefaultInstallLocation')
          WritesAppsAndFeaturesEntry = $true
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'inno'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Existing.Product_is1'
        InstallationMetadata   = [ordered]@{ DefaultInstallLocation = '%LocalAppData%\Existing' }
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Existing Name'
            DisplayVersion = '1.0.0'
            Publisher      = 'Existing Publisher'
            ProductCode    = 'Existing.Product_is1'
          })
      }
      $OldInstaller = $Installer | Copy-Object

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.Product_is1'
      $Result.InstallationMetadata.DefaultInstallLocation | Should -Be '%LocalAppData%\Existing'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Existing Name'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '1.0.0'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'Existing Publisher'
      $Result.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'Existing.Product_is1'
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }) | Should -BeNullOrEmpty
    }

    It 'Preserves existing ARP metadata with a warning when the outer Inno installer cannot own it' {
      Mock Get-InnoInfo {
        [pscustomobject]@{
          ProductCode                = 'Outer.Inno.Product'
          DisplayName                = 'Outer Inno Name'
          DisplayVersion             = '4.0.0'
          Publisher                  = 'Outer Inno Publisher'
          WritesAppsAndFeaturesEntry = $false
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'inno'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Nested.Product'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Nested Product'
            DisplayVersion = '1.0.0'
            ProductCode    = 'Nested.Product'
            InstallerType  = 'exe'
          })
      }
      $OldInstaller = $Installer | Copy-Object

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Nested.Product'
      $Result.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'Nested.Product'
      $Script:LogMessages.Message | Should -Contain 'Inno Setup reports that the outer installer does not write a visible Apps & Features entry; existing ARP metadata belongs to a nested payload or custom registration'
      Should -Invoke Get-InnoInfo -Exactly 1
    }

    It 'Preserves existing ARP metadata for a source-backed NSIS nested-payload wrapper' {
      Mock Get-NSISInfo {
        [pscustomobject]@{
          InstallerType                 = 'Nullsoft'
          WritesAppsAndFeaturesEntry    = $false
          DelegatesAppsAndFeaturesEntry = $true
          ExtractedFiles                = @('$PLUGINSDIR\setup.exe')
          Warnings                      = @('Nested installer owns ARP registration')
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'nullsoft'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Nested.Product'
        AppsAndFeaturesEntries = @([ordered]@{ DisplayVersion = '1.0.0'; InstallerType = 'exe' })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Nested.Product'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '1.0.0'
      $Script:LogMessages.Message | Should -Contain 'NSIS: Nested installer owns ARP registration'
      $Script:LogMessages.Message | Should -Contain 'NSIS reports that the outer installer does not write a visible Apps & Features entry; existing ARP metadata belongs to a nested payload or custom registration'
    }

    It 'Validates NSIS even when the task explicitly supplies matching fields' {
      Mock Get-NSISInfo {
        [pscustomobject]@{
          InstallerType              = 'Nullsoft'
          ProductCode                = 'Parsed.Product'
          DisplayName                = 'Parsed Product'
          DisplayVersion             = '2.0.0'
          Publisher                  = 'Parsed Publisher'
          WritesAppsAndFeaturesEntry = $true
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'nullsoft'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Old.NSIS.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{
          ProductCode            = 'Task.Product'
          AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Task Product' })
        }) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Old.NSIS.Product'
      Should -Invoke Get-NSISInfo -Exactly 1
    }

    It 'Updates MSI fields from one aggregate parser result' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{NEW-PRODUCT}'
          ProductName                  = 'New MSI Product'
          ProductVersion               = '2.0.0'
          Publisher                    = 'New MSI Publisher'
          UpgradeCode                  = '{UPGRADE}'
          AllUsers                     = '1'
          InstallerBuilder             = 'Advanced Installer'
          AppsAndFeaturesProductCode   = '{NEW-PRODUCT}.msq'
          AppsAndFeaturesInstallerType = 'exe'
          Protocols                    = @('new-protocol')
          FileExtensions               = @('newext')
          Dependencies                 = [ordered]@{ PackageDependencies = @([ordered]@{ PackageIdentifier = 'New.Dependency' }) }
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'msi'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-PRODUCT}.msq'
        Protocols              = @('old-protocol')
        FileExtensions         = @('oldext')
        Dependencies           = [ordered]@{ PackageDependencies = @([ordered]@{ PackageIdentifier = 'Old.Dependency' }) }
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old MSI Product'
            DisplayVersion = '1.0.0'
            Publisher      = 'Old MSI Publisher'
            ProductCode    = '{OLD-PRODUCT}.msq'
            UpgradeCode    = '{UPGRADE}'
            InstallerType  = 'msi'
          })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be '{NEW-PRODUCT}.msq'
      $Result.Protocols | Should -Be @('old-protocol')
      $Result.FileExtensions | Should -Be @('oldext')
      $Result.Dependencies.PackageDependencies[0].PackageIdentifier | Should -Be 'Old.Dependency'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New MSI Product'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'New MSI Publisher'
      $Result.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'exe'
      Should -Invoke Get-MsiInstallerInfo -Exactly 1
    }

    It 'Updates retained MSI metadata when the task only supplies the installer URL' {
      Mock Get-WinGetManifestSchema {
        [ordered]@{
          definitions = [ordered]@{
            Installer = [ordered]@{ properties = [ordered]@{ InstallerUrl = [ordered]@{} } }
          }
          properties  = [ordered]@{
            Installers = [ordered]@{
              items = [ordered]@{ properties = [ordered]@{ InstallerUrl = [ordered]@{} } }
            }
          }
        }
      }
      Mock Test-YamlObject { $true }
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{NEW-PRODUCT}'
          ProductName                  = 'New MSI Product'
          ProductVersion               = '2.0.0'
          Publisher                    = 'New MSI Publisher'
          UpgradeCode                  = '{NEW-UPGRADE}'
          AllUsers                     = '1'
          InstallerBuilder             = 'MSI'
          AppsAndFeaturesInstallerType = 'msi'
        }
      }
      $OldInstaller = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'msi'
        InstallerUrl           = 'https://example.test/old-installer.msi'
        InstallerSha256        = 'OLD-HASH'
        ProductCode            = '{OLD-PRODUCT}'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old MSI Product'
            DisplayVersion = '1.0.0'
            Publisher      = 'Old MSI Publisher'
            ProductCode    = '{OLD-PRODUCT}'
            UpgradeCode    = '{OLD-UPGRADE}'
            InstallerType  = 'msi'
          })
      }
      $InstallerEntry = [ordered]@{
        Architecture = 'x64'
        InstallerUrl = $Script:InstallerUrl
      }

      $Result = Update-WinGetInstallerManifestInstallers -OldInstallers @($OldInstaller) -InstallerEntries @($InstallerEntry) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be '{NEW-PRODUCT}'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New MSI Product'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '2.0.0'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'New MSI Publisher'
      $Result.AppsAndFeaturesEntries[0].ProductCode | Should -Be '{NEW-PRODUCT}'
      $Result.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{NEW-UPGRADE}'
      Should -Invoke Get-MsiInstallerInfo -Exactly 1
    }

    It 'Preserves an authored AppsAndFeaturesEntries InstallerType that conflicts with a matching WiX installer' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{NEW-WIX-PRODUCT}'
          ProductName                  = 'WiX Product'
          ProductVersion               = '2.0.0'
          Publisher                    = 'WiX Publisher'
          UpgradeCode                  = '{WIX-UPGRADE}'
          AllUsers                     = '1'
          InstallerBuilder             = 'WiX'
          AppsAndFeaturesProductCode   = '{NEW-WIX-PRODUCT}'
          AppsAndFeaturesInstallerType = 'wix'
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'wix'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-WIX-PRODUCT}'
        AppsAndFeaturesEntries = @([ordered]@{ UpgradeCode = '{WIX-UPGRADE}'; InstallerType = 'msi' })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      # The authored type is not overwritten or removed by parser-normalized evidence
      $Result.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'msi'
    }

    It 'Uses NestedInstallerType when deciding whether to materialize an AppsAndFeaturesEntries type' {
      Mock Expand-TempArchive { $TestDrive }
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{NEW-NESTED-WIX-PRODUCT}'
          ProductName                  = 'Nested WiX Product'
          ProductVersion               = '2.0.0'
          Publisher                    = 'WiX Publisher'
          UpgradeCode                  = '{NESTED-WIX-UPGRADE}'
          AllUsers                     = '1'
          InstallerBuilder             = 'WiX'
          AppsAndFeaturesProductCode   = '{NEW-NESTED-WIX-PRODUCT}'
          AppsAndFeaturesInstallerType = 'wix'
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x86'
        InstallerType          = 'zip'
        NestedInstallerType    = 'wix'
        NestedInstallerFiles   = @([ordered]@{ RelativeFilePath = 'nested.msi' })
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-NESTED-WIX-PRODUCT}'
        AppsAndFeaturesEntries = @([ordered]@{ UpgradeCode = '{NESTED-WIX-UPGRADE}' })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.AppsAndFeaturesEntries[0].Contains('InstallerType') | Should -BeFalse
    }

    It 'Preserves DefaultInstallLocation when a known installer parser cannot derive it' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{DRAW-PRODUCT}'
          ProductName                  = 'draw.io'
          ProductVersion               = '30.3.6'
          Publisher                    = 'JGraph'
          UpgradeCode                  = '{DRAW-UPGRADE}'
          AllUsers                     = '1'
          InstallerBuilder             = 'WiX'
          AppsAndFeaturesProductCode   = '{DRAW-PRODUCT}'
          AppsAndFeaturesInstallerType = 'wix'
        }
      }
      $Installer = [ordered]@{
        Architecture         = 'x64'
        InstallerType        = 'wix'
        InstallerUrl         = $Script:InstallerUrl
        ProductCode          = '{DRAW-PRODUCT}'
        InstallationMetadata = [ordered]@{ DefaultInstallLocation = '%ProgramFiles%/draw.io' }
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.InstallationMetadata.DefaultInstallLocation | Should -Be '%ProgramFiles%/draw.io'
      $Script:LogMessages.Message | Should -Not -Contain "Windows Installer did not return a value for existing installer field 'InstallationMetadata.DefaultInstallLocation'"
    }

    It 'Materializes an EXE ARP type for a Velopack MSI custom uninstall key' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                   = '{NEW-TOWER-MSI}'
          ProductName                   = 'Tower'
          ProductVersion                = '13.1.576.0'
          Publisher                     = 'saas.group'
          UpgradeCode                   = '{TOWER-UPGRADE}'
          AllUsers                      = '2'
          InstallerBuilder              = 'WiX'
          AppsAndFeaturesProductCode    = 'MSI:Tower'
          AppsAndFeaturesInstallerType  = 'exe'
          HasCustomAppsAndFeaturesEntry = $true
          HidesMsiAppsAndFeaturesEntry  = $true
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'wix'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-TOWER-MSI}'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName = 'Tower Deployment Tool'
            ProductCode = '{OLD-TOWER-MSI}'
            UpgradeCode = '{TOWER-UPGRADE}'
          })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'MSI:Tower'
      $Result.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'MSI:Tower'
      $Result.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'exe'
      $Result.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{TOWER-UPGRADE}'
    }

    It 'Accepts and updates a manifest-declared WiX installer built by another MSI tool' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode      = '{PRODUCT}'
          ProductName      = 'MSI Product'
          ProductVersion   = '1.0.0'
          AllUsers         = '1'
          InstallerBuilder = 'InstallShield'
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'wix'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = '{OLD-PRODUCT}'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      # The MSI/WiX builder mismatch is intentionally not validated
      $Result.ProductCode | Should -Be '{PRODUCT}'
    }

    It 'Warns and preserves fields when a manifest-declared NSIS installer cannot be parsed' {
      Mock Get-NSISInfo { throw 'The NSIS installer header could not be located at a valid aligned archive start' }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'nullsoft'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Old.NSIS.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Old.NSIS.Product'
      $Script:LogMessages.Message | Should -Contain "Failed to validate and parse the manifest-declared 'nullsoft' installer: The NSIS installer header could not be located at a valid aligned archive start; existing fields are preserved"
    }

    It 'Still throws when a manifest-declared MSIX installer cannot be parsed' {
      Mock Get-MSIXInfo { throw 'The package is not a valid MSIX package' }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'msix'
        InstallerUrl  = $Script:InstallerUrl
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw '*not a valid MSIX package*'
    }

    It 'Returns a uniform result shape with warnings for every known family' {
      Mock Get-MsiInstallerInfo { [pscustomobject]@{ ProductCode = '{P}'; InstallerBuilder = 'WiX'; Warnings = @() } }
      Mock Get-BurnInfo { [pscustomobject]@{ InstallerType = 'Burn'; ProductCode = '{B}'; Warnings = @() } }
      Mock Get-NSISInfo { [pscustomobject]@{ InstallerType = 'Nullsoft'; ProductCode = 'N'; DisplayName = 'N'; DisplayVersion = '1.0'; Warnings = @() } }
      Mock Get-InnoInfo { [pscustomobject]@{ InstallerType = 'Inno'; ProductCode = 'I'; Warnings = @() } }
      Mock Get-MSIXInfo { [pscustomobject]@{ InstallerType = 'msix'; Version = '1.0.0.0'; Warnings = @() } }

      foreach ($Case in @(
          @{ Type = 'msi'; Parser = 'Windows Installer' },
          @{ Type = 'wix'; Parser = 'Windows Installer' },
          @{ Type = 'burn'; Parser = 'Burn' },
          @{ Type = 'nullsoft'; Parser = 'NSIS' },
          @{ Type = 'inno'; Parser = 'Inno Setup' },
          @{ Type = 'msix'; Parser = 'MSIX/AppX' }
        )) {
        $Info = Get-WinGetKnownInstallerManifestInfo -Path $Script:InstallerPath -InstallerType $Case.Type
        $Info.ParserName | Should -Be $Case.Parser
        @($Info.InputObject).Count | Should -Be 1
        $Info.PSObject.Properties.Name | Should -Contain 'Warnings'
        $Info.Warnings | Should -Be @()
      }
    }

    It 'Forwards Inno parser warnings like NSIS warnings' {
      Mock Get-InnoInfo {
        [pscustomobject]@{
          InstallerType              = 'Inno'
          ProductCode                = 'Inno.Product'
          DisplayName                = 'Inno Product'
          DisplayVersion             = '1.0.0'
          Publisher                  = 'Inno Publisher'
          WritesAppsAndFeaturesEntry = $true
          Warnings                   = @('Inno parser caveat')
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'inno'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Old.Inno.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Inno.Product'
      $Script:LogMessages.Message | Should -Contain 'Inno Setup: Inno parser caveat'
    }

    It 'Throws on a cross-major-type mismatch between script installer families' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = 'NSIS/Nullsoft'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'nullsoft' } }) }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'inno'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Old.Inno.Product'
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw "*The manifest-declared 'inno' installer was detected as 'nullsoft'*"
    }

    It 'Throws when a manifest-declared MSI installer is detected as an EXE family' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = '7z SFX'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'exe # 7z SFX' } }) }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'msi'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = '{OLD-PRODUCT}'
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw "*The manifest-declared 'msi' installer was detected as 'exe # 7z SFX'*"
    }

    It 'Warns and rolls back when strict metadata application fails, keeping the hash' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{NEW-PRODUCT}'
          ProductName                  = 'WiX Product'
          ProductVersion               = '2.0.0'
          AllUsers                     = '1'
          UpgradeCode                  = '{NO-MATCH-UPGRADE}'
          InstallerBuilder             = 'WiX'
          AppsAndFeaturesInstallerType = 'wix'
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'wix'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-PRODUCT}'
        AppsAndFeaturesEntries = @(
          [ordered]@{ UpgradeCode = '{OTHER-UPGRADE}' }
          [ordered]@{ UpgradeCode = '{THIRD-UPGRADE}' }
        )
      }
      $OldSha256 = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      # Parser-applied changes are rolled back, but the hash update is kept
      $Result.ProductCode | Should -Be '{OLD-PRODUCT}'
      $Result.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{OTHER-UPGRADE}'
      $Result.AppsAndFeaturesEntries[1].UpgradeCode | Should -Be '{THIRD-UPGRADE}'
      $Result.InstallerSha256 | Should -Not -BeNullOrEmpty
      $Result.InstallerSha256 | Should -Not -Be $OldSha256
      $Script:LogMessages.Message | Should -Contain 'Windows Installer metadata did not match any existing AppsAndFeaturesEntries item; existing fields are preserved'
    }

    It 'Throws on a cross-major-type mismatch between Burn and WiX' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = 'MSI'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'wix' } }) }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'burn'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = '{OLD-BUNDLE}'
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw "*The manifest-declared 'burn' installer was detected as 'wix'*"
    }

    It 'Parses a plain MSI while keeping the declared WiX type on a family mismatch' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = 'MSI'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'msi' } }) }
      }
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{NEW-PRODUCT}'
          ProductName                  = 'MSI Product'
          ProductVersion               = '2.0.0'
          AllUsers                     = '1'
          InstallerBuilder             = 'Advanced Installer'
          AppsAndFeaturesInstallerType = 'msi'
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'wix'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = '{OLD-PRODUCT}'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.InstallerType | Should -Be 'wix'
      $Result.ProductCode | Should -Be '{NEW-PRODUCT}'
      $Script:LogMessages.Message | Should -Contain "The manifest-declared 'wix' installer was detected as 'msi'; the declared type is kept and metadata is updated from the detected parser"
    }

    It 'Throws when a manifest-declared MSIX installer is detected as another type' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = 'MSI'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'msi' } }) }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'msix'
        InstallerUrl  = $Script:InstallerUrl
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw "*The manifest-declared 'msix' installer was detected as 'msi'*"
    }

    It 'Preserves an authored AppsAndFeaturesEntries InstallerType that disagrees with the normalized type' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                   = '{PRODUCT}'
          ProductName                   = 'Inconclusive WiX Product'
          ProductVersion                = '1.0.0'
          AllUsers                      = '1'
          InstallerBuilder              = 'Unknown'
          AppsAndFeaturesInstallerType  = 'msi'
          HasCustomAppsAndFeaturesEntry = $false
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'wix'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-PRODUCT}'
        AppsAndFeaturesEntries = @([ordered]@{ InstallerType = 'msi' })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be '{PRODUCT}'
      $Result.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'msi'
    }

    It 'Removes only an AppsAndFeaturesEntries InstallerType that restates the effective type' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                   = '{PRODUCT}'
          ProductName                   = 'WiX Product'
          ProductVersion                = '1.0.0'
          AllUsers                      = '1'
          UpgradeCode                   = '{OLD-UPGRADE}'
          InstallerBuilder              = 'WiX'
          AppsAndFeaturesInstallerType  = 'wix'
          HasCustomAppsAndFeaturesEntry = $false
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'wix'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-PRODUCT}'
        AppsAndFeaturesEntries = @(
          [ordered]@{ InstallerType = 'wix'; ProductCode = '{OLD-PRODUCT}'; UpgradeCode = '{OLD-UPGRADE}' }
          [ordered]@{ InstallerType = 'nullsoft'; ProductCode = '{OLD-PRODUCT}' }
        )
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.AppsAndFeaturesEntries[0].Contains('InstallerType') | Should -BeFalse
      # The authored EXE-style type of a bootstrap MSI is author intent and is preserved
      $Result.AppsAndFeaturesEntries[1].InstallerType | Should -Be 'nullsoft'
    }

    It 'Removes empty dictionaries and arrays from the installer entry' {
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        InstallerSha256        = 'TASK-HASH'
        Protocols              = @()
        InstallerSwitches      = [ordered]@{}
        Dependencies           = [ordered]@{ PackageDependencies = @() }
        AppsAndFeaturesEntries = @(
          [ordered]@{}
          [ordered]@{ UpgradeCode = '{MEANINGFUL-UPGRADE}' }
        )
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.Contains('Protocols') | Should -BeFalse
      $Result.Contains('InstallerSwitches') | Should -BeFalse
      $Result.Contains('Dependencies') | Should -BeFalse
      @($Result.AppsAndFeaturesEntries).Count | Should -Be 1
      $Result.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{MEANINGFUL-UPGRADE}'
    }

    It 'Removes empty AppsAndFeaturesEntries items while preserving meaningful entries' {
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        InstallerSha256        = 'TASK-HASH'
        AppsAndFeaturesEntries = @(
          [ordered]@{}
          [ordered]@{ UpgradeCode = '{MEANINGFUL-UPGRADE}' }
        )
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      @($Result.AppsAndFeaturesEntries).Count | Should -Be 1
      $Result.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{MEANINGFUL-UPGRADE}'
    }

    It 'parses Burn registrations that omit the optional PerMachine attribute' {
      Mock Get-BurnEngineInfo -ModuleName Burn { [pscustomobject]@{ BundleCode = [guid]::NewGuid() } }
      Mock Get-BurnManifest -ModuleName Burn {
        [xml]'<BurnManifest><Registration Code="{BUNDLE}"><Arp DisplayName="Servo" DisplayVersion="1.0" Publisher="Servo" /></Registration><RelatedBundle Code="{UPGRADE}" /></BurnManifest>'
      }
      Mock Get-BurnScopeInfo -ModuleName Burn { [pscustomobject]@{ DefaultScope = $null; SupportedScopes = @(); SupportsDualScope = $false } }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'burn'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = '{OLD-BUNDLE}'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be '{BUNDLE}'
    }

    It 'Updates generic EXE metadata from a detected Advanced Installer parser result' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Advanced Installer'
              Success = $true
              Result  = [pscustomobject]@{
                Metadata = [pscustomobject]@{
                  InstallerType       = 'AdvancedInstaller'
                  MsiPayloadSelection = [pscustomobject]@{
                    SourceKind      = 'EmbeddedArchive'
                    SelectionMethod = 'PayloadTable'
                  }
                }
              }
            })
          FamilyCandidates = @()
        }
      }
      Mock Get-AdvancedInstallerMsiInfo {
        param($Installer, $Architecture)
        [pscustomobject]@{
          ProductName                  = "New Advanced Product $Architecture"
          ProductVersion               = '5.0.0'
          Publisher                    = 'New Advanced Publisher'
          ProductCode                  = '{MSI-PRODUCT}'
          AppsAndFeaturesProductCode   = "Advanced.Product.$Architecture"
          UpgradeCode                  = '{ADVANCED-UPGRADE}'
          AppsAndFeaturesInstallerType = 'exe'
          PackageArchitecture          = $Architecture
          SelectedMsiPath              = "payload.$Architecture.msi"
          SelectionMethod              = 'PayloadTable'
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Old.Advanced.Product'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old Advanced Product'
            DisplayVersion = '4.0.0'
            Publisher      = 'Old Advanced Publisher'
            ProductCode    = 'Old.Advanced.Product'
            UpgradeCode    = '{ADVANCED-UPGRADE}'
            InstallerType  = 'msi'
          })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Advanced.Product.x64'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New Advanced Product x64'
      # The authored type is preserved even when the nested payload reports an EXE-style entry
      $Result.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'msi'

      $X86Installer = [ordered]@{
        Architecture           = 'x86'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Old.Advanced.Product'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old Advanced Product'
            DisplayVersion = '4.0.0'
            Publisher      = 'Old Advanced Publisher'
            ProductCode    = 'Old.Advanced.Product'
            UpgradeCode    = '{ADVANCED-UPGRADE}'
            InstallerType  = 'msi'
          })
      }
      $X86Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $X86Installer -OldInstaller ($X86Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $X86Result.ProductCode | Should -Be 'Advanced.Product.x86'
      $X86Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New Advanced Product x86'
      $Script:LogMessages.Where({ $_.Level -eq 'Verbose' }).Message | Should -Contain "Advanced Installer selected MSI 'payload.x64.msi' using 'PayloadTable'"
      $Script:LogMessages.Where({ $_.Level -eq 'Verbose' }).Message | Should -Contain "Advanced Installer selected MSI 'payload.x86.msi' using 'PayloadTable'"
      Should -Invoke Get-WinGetInstallerAnalysis -Exactly 2 -ParameterFilter { -not $ExtractEmbeddedMsi }
      Should -Invoke Get-AdvancedInstallerMsiInfo -Exactly 1 -ParameterFilter { $Architecture -ceq 'x64' }
      Should -Invoke Get-AdvancedInstallerMsiInfo -Exactly 1 -ParameterFilter { $Architecture -ceq 'x86' }
    }

    It 'Parses same-URL Advanced Installer entries independently by architecture' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Advanced Installer'
              Success = $true
              Result  = [pscustomobject]@{
                Metadata = [pscustomobject]@{
                  InstallerType       = 'AdvancedInstaller'
                  MsiPayloadSelection = [pscustomobject]@{
                    SourceKind      = 'EmbeddedMsi'
                    SelectionMethod = 'PayloadTable'
                  }
                }
              }
            })
          FamilyCandidates = @()
        }
      }
      Mock Get-AdvancedInstallerMsiInfo {
        param($Installer, $Architecture)
        [pscustomobject]@{
          ProductName                  = "Advanced Product $Architecture"
          ProductVersion               = '5.0.0'
          Publisher                    = 'Advanced Publisher'
          ProductCode                  = "MSI.Product.$Architecture"
          AppsAndFeaturesProductCode   = "ARP.Product.$Architecture"
          UpgradeCode                  = "Upgrade.$Architecture"
          AppsAndFeaturesInstallerType = 'msi'
          PackageArchitecture          = $Architecture
          SelectedMsiPath              = "payload.$Architecture.msi"
          SelectionMethod              = 'PayloadTable'
        }
      }
      $X86Installer = [ordered]@{
        Architecture           = 'x86'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        InstallerSha256        = 'TASK-SUPPLIED-HASH'
        ProductCode            = 'Old.Product.x86'
        AppsAndFeaturesEntries = @([ordered]@{ UpgradeCode = 'Upgrade.x86'; InstallerType = 'msi' })
      }
      $X64Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        InstallerSha256        = 'TASK-SUPPLIED-HASH'
        ProductCode            = 'Old.Product.x64'
        AppsAndFeaturesEntries = @([ordered]@{ UpgradeCode = 'Upgrade.x64'; InstallerType = 'msi' })
      }

      $X86Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $X86Installer -OldInstaller ($X86Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger
      $X64Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $X64Installer -OldInstaller ($X64Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -Installers @($X86Result) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $X86Result.ProductCode | Should -Be 'ARP.Product.x86'
      $X64Result.ProductCode | Should -Be 'ARP.Product.x64'
      Should -Invoke Get-WinGetInstallerAnalysis -Exactly 2
      Should -Invoke Get-AdvancedInstallerMsiInfo -Exactly 1 -ParameterFilter { $Architecture -ceq 'x86' }
      Should -Invoke Get-AdvancedInstallerMsiInfo -Exactly 1 -ParameterFilter { $Architecture -ceq 'x64' }
    }

    It 'Preserves metadata when Advanced Installer selects an online MainAppURL payload' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Advanced Installer'
              Success = $true
              Result  = [pscustomobject]@{
                Metadata = [pscustomobject]@{
                  InstallerType       = 'AdvancedInstaller'
                  MsiPayloadSelection = [pscustomobject]@{
                    SourceKind = 'Download'
                    MainAppUrl = 'https://example.test/product.msi'
                  }
                }
              }
            })
          FamilyCandidates = @()
        }
      }
      Mock Get-AdvancedInstallerMsiInfo { throw 'The embedded MSI parser should not be called' }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.Advanced.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.Advanced.Product'
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message | Should -BeLike "*MainAppURL 'https://example.test/product.msi'*"
      Should -Invoke Get-AdvancedInstallerMsiInfo -Exactly 0
    }

    It 'Updates generic EXE metadata from a detected Squirrel parser result' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Squirrel/Velopack'
              Success = $true
              Result  = [pscustomobject]@{
                Metadata = [pscustomobject]@{
                  InstallerType          = 'Squirrel'
                  ProductCode            = 'New.Squirrel.Product'
                  DisplayName            = 'New Squirrel Product'
                  DisplayVersion         = '2.0.0'
                  Publisher              = 'New Squirrel Publisher'
                  Scope                  = 'machine'
                  DefaultInstallLocation = '%LocalAppData%\New.Squirrel.Product'
                }
              }
            })
          FamilyCandidates = @()
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        Scope                  = 'user'
        ProductCode            = 'Old.Squirrel.Product'
        InstallationMetadata   = [ordered]@{ DefaultInstallLocation = '%LocalAppData%\Old.Squirrel.Product' }
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old Squirrel Product'
            DisplayVersion = '1.0.0'
            Publisher      = 'Old Squirrel Publisher'
            ProductCode    = 'Old.Squirrel.Product'
          })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      @($Script:LogMessages.Where({ $_.Level -eq 'Warning' })).Count | Should -Be 0
      $Result.ProductCode | Should -Be 'New.Squirrel.Product'
      $Result.Scope | Should -Be 'user'
      $Result.InstallationMetadata.DefaultInstallLocation | Should -Be '%LocalAppData%\New.Squirrel.Product'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New Squirrel Product'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '2.0.0'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'New Squirrel Publisher'
    }

    It 'Resolves a Chromium Setup ProductCode from the manifest channel switch' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Chromium Setup'
              Success = $true
              Result  = [pscustomobject]@{
                Variant        = 'ChromiumMiniInstaller'
                Publisher      = 'Google LLC'
                ProductName    = 'Google Chrome Installer'
                ProductCode    = $null
                DisplayName    = 'Google Chrome Installer'
                DisplayVersion = '152.0.7953.0'
                InstallModes   = @(
                  [pscustomobject]@{ Index = 0; InstallSwitch = ''; ProductCode = 'Google Chrome' }
                  [pscustomobject]@{ Index = 1; InstallSwitch = 'chrome-sxs'; ProductCode = 'Google Chrome SxS' }
                )
              }
            })
          FamilyCandidates = @()
        }
      }
      $Installer = [ordered]@{
        Architecture      = 'x64'
        InstallerType     = 'exe'
        InstallerUrl      = $Script:InstallerUrl
        InstallerSwitches = [ordered]@{ Custom = '--chrome-sxs --do-not-launch-chrome' }
        ProductCode       = 'Google Chrome SxS'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Google Chrome SxS'
      @($Script:LogMessages.Where({ $_.Level -eq 'Warning' })).Count | Should -Be 0
    }

    It 'Uses a source-backed ProductCode returned by a tagged Chromium wrapper' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Chromium Setup'
              Success = $true
              Result  = [pscustomobject]@{
                Variant        = 'Omaha'
                ProductCode    = 'BraveSoftware Brave-Origin-Nightly'
                DisplayName    = 'Brave-Origin-Nightly'
                DisplayVersion = '151.1.94.75'
                Warnings       = @()
              }
            })
          FamilyCandidates = @()
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'BraveSoftware Brave-Origin-Nightly'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -BeExactly 'BraveSoftware Brave-Origin-Nightly'
      @($Script:LogMessages.Where({ $_.Level -eq 'Warning' })).Count | Should -Be 0
    }

    It 'preserves an existing Chromium ProductCode when static evidence cannot resolve the ARP identity' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Chromium Setup'
              Success = $true
              Result  = [pscustomobject]@{
                Variant          = 'ChromiumUpdater'
                ProductCode      = $null
                UnresolvedFields = @('ProductCode')
                Warnings         = @()
              }
            })
          FamilyCandidates = @()
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Zoho Ulaa'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -BeExactly 'Zoho Ulaa'
      @($Script:LogMessages.Where({ $_.Level -eq 'Warning' })).Count | Should -Be 0
    }

    It 'Uses InstallShield marker evidence before parsing an embedded MSI' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @()
          FamilyCandidates = @([pscustomobject]@{ Family = 'InstallShield'; Confidence = 'medium' })
        }
      }
      Mock Get-InstallShieldInfo {
        [pscustomobject]@{
          InstallerType       = 'InstallShield'
          Variant             = 'Basic MSI or InstallScript MSI'
          HasMsi              = $true
          MsiFiles            = @('payload.msi')
          MsiPayloadSelection = [pscustomobject]@{
            SelectedMsiPath = 'payload.msi'
            SelectionMethod = 'SetupIni'
          }
          Warnings            = @()
        }
      }
      Mock Get-InstallShieldMsiInfo {
        [pscustomobject]@{
          ProductName                  = 'New InstallShield Product'
          ProductVersion               = '4.0.0'
          Publisher                    = 'New InstallShield Publisher'
          ProductCode                  = '{INSTALLSHIELD-MSI}'
          AppsAndFeaturesProductCode   = '{INSTALLSHIELD-MSI}'
          UpgradeCode                  = '{INSTALLSHIELD-UPGRADE}'
          AppsAndFeaturesInstallerType = 'msi'
          PackageArchitecture          = 'x64'
          SelectedMsiPath              = 'payload.msi'
          SelectionMethod              = 'SetupIni'
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-INSTALLSHIELD}'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old InstallShield Product'
            DisplayVersion = '3.0.0'
            Publisher      = 'Old InstallShield Publisher'
            ProductCode    = '{OLD-INSTALLSHIELD}'
            UpgradeCode    = '{INSTALLSHIELD-UPGRADE}'
            InstallerType  = 'msi'
          })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      @($Script:LogMessages.Where({ $_.Level -eq 'Warning' })).Count | Should -Be 0
      $Result.ProductCode | Should -Be '{INSTALLSHIELD-MSI}'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New InstallShield Product'
      $Script:LogMessages.Where({ $_.Level -eq 'Verbose' }).Message | Should -Contain "InstallShield selected MSI 'payload.msi' using 'SetupIni'"
      Should -Invoke Get-InstallShieldInfo -Exactly 1
      Should -Invoke Get-InstallShieldMsiInfo -Exactly 1 -ParameterFilter { $Installer.MsiPayloadSelection.SelectedMsiPath -ceq 'payload.msi' -and -not $Name }
    }

    It 'Warns and preserves metadata for InstallShield payloads without an MSI' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @()
          FamilyCandidates = @([pscustomobject]@{ Family = 'InstallShield'; Confidence = 'medium' })
        }
      }
      Mock Get-InstallShieldInfo {
        [pscustomobject]@{
          InstallerType = 'InstallShield'
          Variant       = 'InstallScript'
          HasMsi        = $false
          MsiFiles      = @()
          Warnings      = @()
        }
      }
      Mock Get-InstallShieldMsiInfo { throw 'The MSI parser should not be called' }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.InstallShield.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.InstallShield.Product'
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message | Should -BeLike "*'InstallScript' payload does not contain an MSI*"
      Should -Invoke Get-InstallShieldMsiInfo -Exactly 0
    }

    It 'Warns and preserves generic EXE metadata when detection fails' {
      Mock Get-WinGetInstallerAnalysis { throw 'synthetic analyzer failure' }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.Product'
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message | Should -BeLike '*synthetic analyzer failure*'
    }

    It 'Extracts only the selected nested installer from a ZIP archive' {
      $ArchivePath = Join-Path $TestDrive 'large-archive-without-extension'
      $Archive = [IO.Compression.ZipFile]::Open($ArchivePath, [IO.Compression.ZipArchiveMode]::Create)
      try {
        $NestedEntry = $Archive.CreateEntry('payload/setup.exe')
        $NestedStream = $NestedEntry.Open()
        try { $NestedStream.Write([byte[]](1, 2, 3, 4)) } finally { $NestedStream.Dispose() }

        $UnrelatedEntry = $Archive.CreateEntry('unrelated/large.bin', [IO.Compression.CompressionLevel]::NoCompression)
        $UnrelatedStream = $UnrelatedEntry.Open()
        try {
          $Buffer = [byte[]]::new(1MB)
          1..8 | ForEach-Object { $UnrelatedStream.Write($Buffer) }
        } finally {
          $UnrelatedStream.Dispose()
        }
      } finally {
        $Archive.Dispose()
      }

      $Script:ParsedNestedPath = $null
      Mock Get-NSISInfo {
        param($Path)
        $Script:ParsedNestedPath = $Path
        [pscustomobject]@{
          ProductCode                = 'Nested.NSIS.Product'
          DisplayName                = 'Nested NSIS Product'
          DisplayVersion             = '1.0.0'
          Publisher                  = 'Nested Publisher'
          WritesAppsAndFeaturesEntry = $true
        }
      }
      $ArchiveUrl = 'https://example.test/archive.zip'
      $Installer = [ordered]@{
        Architecture         = 'x64'
        InstallerType        = 'zip'
        NestedInstallerType  = 'nullsoft'
        NestedInstallerFiles = @([ordered]@{ RelativeFilePath = 'payload\setup.exe' })
        InstallerUrl         = $ArchiveUrl
        ProductCode          = 'Old.Nested.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{ $ArchiveUrl = $ArchivePath }) -Logger $Script:Logger

      try {
        $Result.ProductCode | Should -Be 'Nested.NSIS.Product'
        $Script:ParsedNestedPath | Should -Exist
        $ExtractionRoot = Split-Path (Split-Path $Script:ParsedNestedPath -Parent) -Parent
        Join-Path $ExtractionRoot 'unrelated\large.bin' | Should -Not -Exist
      } finally {
        if ($Script:ParsedNestedPath) {
          Remove-Item -LiteralPath (Split-Path (Split-Path $Script:ParsedNestedPath -Parent) -Parent) -Recurse -Force -ErrorAction SilentlyContinue
        }
      }
      Should -Invoke Get-NSISInfo -Exactly 1
    }

    It 'Keeps full ZIP extraction available for existing Expand-TempArchive callers' {
      $ArchivePath = Join-Path $TestDrive 'compatibility.zip'
      $Archive = [IO.Compression.ZipFile]::Open($ArchivePath, [IO.Compression.ZipArchiveMode]::Create)
      try {
        foreach ($Name in @('first.txt', 'nested/second.txt')) {
          $Entry = $Archive.CreateEntry($Name)
          $EntryStream = $Entry.Open()
          try { $EntryStream.Write([Text.Encoding]::UTF8.GetBytes($Name)) } finally { $EntryStream.Dispose() }
        }
      } finally {
        $Archive.Dispose()
      }

      $ExpandedPath = Expand-TempArchive -Path $ArchivePath
      try {
        Join-Path $ExpandedPath 'first.txt' | Should -Exist
        Join-Path $ExpandedPath 'nested\second.txt' | Should -Exist
      } finally {
        Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

Describe 'Format-WinGetManifest' {
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
}
