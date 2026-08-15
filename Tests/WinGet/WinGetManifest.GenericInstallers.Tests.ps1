. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\WinGetManifestTestSetup.ps1')

Describe 'WinGet generic installer manifest updates' -Tag Unit {
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
          DisplayName                  = "New Advanced Product $Architecture"
          DisplayVersion               = '5.0.0'
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
          DisplayName                  = "Advanced Product $Architecture"
          DisplayVersion               = '5.0.0'
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

    It 'Preserves metadata for an Advanced Installer MSI/MSIX platform wrapper' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Advanced Installer'
              Success = $true
              Result  = [pscustomobject]@{
                Metadata = [pscustomobject]@{
                  InstallerType            = 'AdvancedInstaller'
                  MsiPayloadSelection      = [pscustomobject]@{ SourceKind = 'EmbeddedMsi' }
                  PlatformPayloadSelection = [pscustomobject]@{
                    SelectionMethod    = 'OperatingSystemVersion'
                    LegacyMsiSelection = [pscustomobject]@{ SourceKind = 'EmbeddedMsi' }
                    ModernPayloads     = @([pscustomobject]@{ Name = 'product-x64.msix' })
                  }
                }
              }
            })
          FamilyCandidates = @()
        }
      }
      Mock Get-AdvancedInstallerMsiInfo { throw 'The legacy MSI parser should not update mixed platform metadata automatically' }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.Advanced.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.Advanced.Product'
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message | Should -Contain 'Advanced Installer selects an MSIX/AppX package on supported Windows versions and an MSI on older systems. Existing installed-state fields are preserved until both nested packages are analyzed.'
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

    It 'Preserves an existing ProductCode for Chromium <Variant>' -ForEach @(
      @{ Variant = 'ChromiumMiniInstaller'; ExistingProductCode = 'Google Chrome SxS' }
      @{ Variant = 'ChromiumUpdater'; ExistingProductCode = 'Zoho Ulaa' }
      @{ Variant = 'Omaha'; ExistingProductCode = 'BraveSoftware Brave-Origin-Nightly' }
    ) {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults    = @([pscustomobject]@{
              Name    = 'Chromium Setup'
              Success = $true
              Result  = [pscustomobject]@{
                Variant          = $Variant
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
        ProductCode   = $ExistingProductCode
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -BeExactly $ExistingProductCode
      @($Script:LogMessages.Where({ $_.Level -eq 'Warning' })).Count | Should -Be 0
    }

    It 'Uses InstallShield marker evidence before parsing an embedded MSI' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults = @()
          RoutingHints  = @([pscustomobject]@{ Family = 'InstallShield'; Confidence = 'medium' })
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
          DisplayName                  = 'New InstallShield Product'
          DisplayVersion               = '4.0.0'
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

    It 'Uses detached MSI metadata from a successful InstallShield analyzer result' {
      $MsiInfo = [pscustomobject]@{
        DisplayName                  = 'Detached InstallShield Product'
        DisplayVersion               = '5.0.0'
        Publisher                    = 'Detached Publisher'
        ProductCode                  = '{DETACHED-INSTALLSHIELD-MSI}'
        AppsAndFeaturesProductCode   = '{DETACHED-INSTALLSHIELD-MSI}'
        UpgradeCode                  = '{DETACHED-INSTALLSHIELD-UPGRADE}'
        AppsAndFeaturesInstallerType = 'msi'
        SelectedMsiPath              = 'payload\Detached.msi'
        SelectionMethod              = 'SetupIni'
      }
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults      = @([pscustomobject]@{
              Name    = 'InstallShield'
              Success = $true
              Result  = [pscustomobject]@{
                Family   = 'InstallShield'
                Metadata = [pscustomobject]@{ HasMsi = $true; Variant = 'Basic MSI or InstallScript MSI'; Warnings = @() }
                MsiInfo  = $MsiInfo
              }
            })
          DetectedFamilies   = @()
          RoutingHints       = @()
          RejectedCandidates = @()
        }
      }
      Mock Get-InstallShieldInfo { throw 'The outer InstallShield package must not be extracted again' }
      Mock Get-InstallShieldMsiInfo { throw 'Detached MSI metadata must not be reparsed after cleanup' }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = '{OLD-INSTALLSHIELD}'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName = 'Old InstallShield Product'
            ProductCode = '{OLD-INSTALLSHIELD}'
            UpgradeCode = '{DETACHED-INSTALLSHIELD-UPGRADE}'
          })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be '{DETACHED-INSTALLSHIELD-MSI}'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Detached InstallShield Product'
      Should -Invoke Get-InstallShieldInfo -Exactly 0
      Should -Invoke Get-InstallShieldMsiInfo -Exactly 0
    }

    It 'Uses InstallScript ARP evidence when an InstallShield payload has no MSI' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults = @()
          RoutingHints  = @([pscustomobject]@{ Family = 'InstallShield'; Confidence = 'medium' })
        }
      }
      Mock Get-InstallShieldInfo {
        $InstallScriptInfo = [pscustomobject]@{
          InstallerType                = 'InstallShield InstallScript'
          ProductCode                  = '{INSTALLSCRIPT-PRODUCT}'
          DisplayName                  = 'InstallScript Product'
          DisplayVersion               = $null
          Publisher                    = 'InstallScript Publisher'
          Scope                        = $null
          DefaultInstallLocation       = $null
          WritesAppsAndFeaturesEntry   = $true
          AppsAndFeaturesProductCode   = '{INSTALLSCRIPT-PRODUCT}'
          AppsAndFeaturesInstallerType = 'exe'
          AppsAndFeaturesEntries       = @([pscustomobject]@{
              ProductCode   = '{INSTALLSCRIPT-PRODUCT}'
              DisplayName   = 'InstallScript Product'
              Publisher     = 'InstallScript Publisher'
              InstallerType = 'exe'
            })
          UnresolvedFields             = @('DisplayVersion', 'Scope', 'DefaultInstallLocation')
          Warnings                     = @('InstallScript ARP defaults require VM validation')
        }
        [pscustomobject]@{
          InstallerType     = 'InstallShield'
          Variant           = 'InstallScript'
          HasMsi            = $false
          MsiFiles          = @()
          InstallScriptInfo = $InstallScriptInfo
          Warnings          = @('InstallScript ARP defaults require VM validation')
        }
      }
      Mock Get-InstallShieldMsiInfo { throw 'The MSI parser should not be called' }
      $Installer = [ordered]@{
        Architecture           = 'x64'
        InstallerType          = 'exe'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Existing.InstallShield.Product'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName = 'Old InstallScript Product'
            Publisher   = 'Old InstallScript Publisher'
            ProductCode = 'Existing.InstallShield.Product'
          })
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be '{INSTALLSCRIPT-PRODUCT}'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'InstallScript Product'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'InstallScript Publisher'
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message | Should -Contain 'InstallShield InstallScript: InstallScript ARP defaults require VM validation'
      Should -Invoke Get-InstallShieldMsiInfo -Exactly 0
    }

    It 'Logs rejected generic EXE routing hints at verbose level without a classification warning' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults      = @([pscustomobject]@{ Name = 'CreateInstall'; Success = $false; Error = 'No supported GEA archive' })
          DetectedFamilies   = @()
          RoutingHints       = @([pscustomobject]@{ Family = 'CreateInstall'; Confidence = 'low' })
          RejectedCandidates = @([pscustomobject]@{
              Family           = 'CreateInstall'
              EvidenceKind     = 'Heuristic'
              IsOuterContainer = $false
              ParserName       = 'CreateInstall'
              Error            = 'No supported GEA archive'
            })
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.Product'
      @($Script:LogMessages.Where({ $_.Level -eq 'Warning' })).Count | Should -Be 0
      ($Script:LogMessages.Where({ $_.Level -eq 'Verbose' }).Message -join "`n") | Should -BeLike '*CreateInstall: No supported GEA archive*'
    }

    It 'Preserves generic EXE metadata when multiple incompatible parsers succeed' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          ParserResults      = @(
            [pscustomobject]@{ Name = 'CreateInstall'; Success = $true; Result = [pscustomobject]@{ Family = 'CreateInstall'; Metadata = [pscustomobject]@{ ProductCode = 'CreateInstall.Product' } } }
            [pscustomobject]@{ Name = 'Squirrel/Velopack'; Success = $true; Result = [pscustomobject]@{ Family = 'Squirrel'; Metadata = [pscustomobject]@{ ProductCode = 'Squirrel.Product' } } }
          )
          DetectedFamilies   = @()
          RoutingHints       = @()
          RejectedCandidates = @()
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'exe'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.Product'
      ($Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message -join "`n") | Should -BeLike '*conflicting installer families: CreateInstall, Squirrel*'
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

      $ExpandedPath = Expand-TempArchive -Path $ArchivePath -CollisionAction Rename
      try {
        Join-Path $ExpandedPath 'first.txt' | Should -Exist
        Join-Path $ExpandedPath 'nested\second.txt' | Should -Exist
      } finally {
        Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}
