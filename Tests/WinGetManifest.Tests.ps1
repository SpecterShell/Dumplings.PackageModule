BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\YamlSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\InstallerBridge.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\MSI.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\NSIS.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Inno.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\AdvancedInstaller.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\InstallShield.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\ChromiumSetup.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetInstallerAnalyzer.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetDownload.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifest.psm1') -Force
}

Describe 'WinGet installer manifest metadata updates' {
  InModuleScope WinGetManifest {
    BeforeEach {
      $Script:InstallerPath = Join-Path $TestDrive 'installer.exe'
      [IO.File]::WriteAllBytes($Script:InstallerPath, [byte[]](1, 2, 3, 4))
      $Script:InstallerUrl = 'https://example.test/installer.exe'
      $Script:InstallerFiles = [ordered]@{ $Script:InstallerUrl = $Script:InstallerPath }
      $Script:LogMessages = [System.Collections.Generic.List[object]]::new()
      $Script:Logger = { param($Message, $Level) $Script:LogMessages.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
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

    It 'Updates Inno metadata while preserving the uninstall-key suffix' {
      Mock Get-InnoInfo {
        [pscustomobject]@{
          ProductCode                = 'New.Inno.Product'
          DisplayName                = 'New Inno Name'
          DisplayVersion             = '3.0.0'
          Publisher                  = 'New Inno Publisher'
          WritesAppsAndFeaturesEntry = $true
        }
      }
      $Installer = [ordered]@{
        Architecture           = 'x86'
        InstallerType          = 'inno'
        InstallerUrl           = $Script:InstallerUrl
        ProductCode            = 'Old.Inno.Product_is1'
        AppsAndFeaturesEntries = @([ordered]@{
            DisplayName    = 'Old Inno Name'
            DisplayVersion = '2.0.0'
            Publisher      = 'Old Inno Publisher'
            ProductCode    = 'Old.Inno.Product_is1'
          })
      }
      $OldInstaller = $Installer | Copy-Object

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'New.Inno.Product_is1'
      $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'New Inno Name'
      $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '3.0.0'
      $Result.AppsAndFeaturesEntries[0].Publisher | Should -Be 'New Inno Publisher'
      $Result.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'New.Inno.Product_is1'
      Should -Invoke Get-InnoInfo -Exactly 1
    }

    It 'Rejects known Inno wrappers that cannot own the existing ARP metadata' {
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

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw '*does not write a visible Apps & Features entry*'
      Should -Invoke Get-InnoInfo -Exactly 1
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
          ProductCode                    = '{NEW-PRODUCT}'
          ProductName                    = 'New MSI Product'
          ProductVersion                 = '2.0.0'
          Publisher                      = 'New MSI Publisher'
          UpgradeCode                    = '{UPGRADE}'
          AllUsers                       = '1'
          InstallerBuilder               = 'Advanced Installer'
          AppsAndFeaturesProductCode     = '{NEW-PRODUCT}.msq'
          AppsAndFeaturesInstallerType   = 'exe'
          Protocols                      = @('new-protocol')
          FileExtensions                 = @('newext')
          Dependencies                   = [ordered]@{ PackageDependencies = @([ordered]@{ PackageIdentifier = 'New.Dependency' }) }
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
      Mock Test-YamlObject {}
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

    It 'Does not materialize an AppsAndFeaturesEntries type for a matching WiX installer' {
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

      $Result.AppsAndFeaturesEntries[0].Contains('InstallerType') | Should -BeFalse
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

    It 'Throws when a manifest-declared WiX installer is built by another MSI tool' {
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
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw "*builder is 'InstallShield', not WiX*"
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
          ProductName                    = "New Advanced Product $Architecture"
          ProductVersion                 = '5.0.0'
          Publisher                      = 'New Advanced Publisher'
          ProductCode                    = '{MSI-PRODUCT}'
          AppsAndFeaturesProductCode     = "Advanced.Product.$Architecture"
          UpgradeCode                    = '{ADVANCED-UPGRADE}'
          AppsAndFeaturesInstallerType   = 'exe'
          PackageArchitecture            = $Architecture
          SelectedMsiPath                = "payload.$Architecture.msi"
          SelectionMethod                = 'PayloadTable'
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
      $Result.AppsAndFeaturesEntries[0].Contains('InstallerType') | Should -BeFalse

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
          ProductName                    = "Advanced Product $Architecture"
          ProductVersion                 = '5.0.0'
          Publisher                      = 'Advanced Publisher'
          ProductCode                    = "MSI.Product.$Architecture"
          AppsAndFeaturesProductCode     = "ARP.Product.$Architecture"
          UpgradeCode                    = "Upgrade.$Architecture"
          AppsAndFeaturesInstallerType   = 'msi'
          PackageArchitecture            = $Architecture
          SelectedMsiPath                = "payload.$Architecture.msi"
          SelectionMethod                = 'PayloadTable'
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
          ParserResults = @([pscustomobject]@{
              Name    = 'Chromium Setup'
              Success = $true
              Result  = [pscustomobject]@{
                Variant        = 'ChromiumMiniInstaller'
                Publisher      = 'Google LLC'
                ProductName    = 'Google Chrome Installer'
                ProductCode    = $null
                DisplayName    = 'Google Chrome Installer'
                DisplayVersion = '152.0.7953.0'
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
          ProductName                    = 'New InstallShield Product'
          ProductVersion                 = '4.0.0'
          Publisher                      = 'New InstallShield Publisher'
          ProductCode                    = '{INSTALLSHIELD-MSI}'
          AppsAndFeaturesProductCode     = '{INSTALLSHIELD-MSI}'
          UpgradeCode                    = '{INSTALLSHIELD-UPGRADE}'
          AppsAndFeaturesInstallerType   = 'msi'
          PackageArchitecture            = 'x64'
          SelectedMsiPath                = 'payload.msi'
          SelectionMethod                = 'SetupIni'
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
