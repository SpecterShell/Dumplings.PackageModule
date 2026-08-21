. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\WinGetManifestTestSetup.ps1')

Describe 'WinGet known installer manifest updates' -Tag Unit {
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

    It 'updates the hash without extracting or analyzing when installer analysis is skipped' {
      Mock Get-WinGetKnownInstallerManifestInfo { throw 'The declared parser must not run' }
      Mock Get-WinGetInstallerAnalysis { throw 'The generic analyzer must not run' }
      Mock Expand-TempArchive { throw 'Nested payload extraction must not run' }
      $ArchiveUrl = 'https://example.test/package.zip'
      $Installer = [ordered]@{
        Architecture         = 'x64'
        InstallerType        = 'zip'
        NestedInstallerType  = 'nullsoft'
        NestedInstallerFiles = @([ordered]@{ RelativeFilePath = 'payload\setup.exe' })
        InstallerUrl         = $ArchiveUrl
        ProductCode          = 'Existing.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{ $ArchiveUrl = $Script:InstallerPath }) -SkipInstallerAnalysis -Logger $Script:Logger

      $Result.InstallerSha256 | Should -Be (Get-FileHash -LiteralPath $Script:InstallerPath -Algorithm SHA256).Hash
      $Result.ProductCode | Should -Be 'Existing.Product'
      Should -Invoke Get-WinGetKnownInstallerManifestInfo -Exactly 0
      Should -Invoke Get-WinGetInstallerAnalysis -Exactly 0
      Should -Invoke Expand-TempArchive -Exactly 0
    }

    It 'Excludes non-authoritative parser fields from manifest metadata' {
      $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject @([pscustomobject]@{
          PackageName          = 'Parser package name'
          Scope                = 'machine'
          Protocols            = @('parser-protocol')
          FileExtensions       = @('parserext')
          Dependencies         = [ordered]@{ PackageDependencies = @([ordered]@{ PackageIdentifier = 'Parser.Dependency' }) }
          ElevationRequirement = 'elevationRequired'
        }) -InstallerType 'exe' -OldInstaller ([ordered]@{})

      $Metadata.Contains('DisplayName') | Should -BeFalse
      foreach ($Field in @('Scope', 'ElevationRequirement', 'Protocols', 'FileExtensions', 'Dependencies')) {
        $Metadata.Contains($Field) | Should -BeFalse
      }
    }

    It 'Preserves an existing elevation requirement despite parser evidence' {
      $Installer = [ordered]@{
        Architecture         = 'x64'
        InstallerType        = 'wix'
        ProductCode          = '{OLD-PRODUCT}'
        ElevationRequirement = 'elevatesSelf'
      }
      $Metadata = [ordered]@{
        ProductCode          = '{NEW-PRODUCT}'
        ElevationRequirement = 'elevationRequired'
      }

      Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -Metadata $Metadata -ParserName 'Windows Installer' -DiagnosticCollection ([Collections.Generic.List[object]]::new())

      $Installer.ProductCode | Should -Be '{NEW-PRODUCT}'
      $Installer.ElevationRequirement | Should -Be 'elevatesSelf'
    }

    It 'Preserves different elevation requirements on scope-specific entries' {
      $Installers = @(
        [ordered]@{
          Architecture         = 'x64'
          InstallerType        = 'exe'
          Scope                = 'user'
          ElevationRequirement = 'elevationProhibited'
          ProductCode          = 'User.Product'
        },
        [ordered]@{
          Architecture         = 'x64'
          InstallerType        = 'exe'
          Scope                = 'machine'
          ElevationRequirement = 'elevationRequired'
          ProductCode          = 'Machine.Product'
        }
      )

      foreach ($Installer in $Installers) {
        $Metadata = [ordered]@{
          ProductCode          = "Updated.$($Installer.Scope).Product"
          ElevationRequirement = 'elevatesSelf'
        }
        Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -Metadata $Metadata -ParserName 'Generic EXE' -DiagnosticCollection ([Collections.Generic.List[object]]::new())
      }

      $Installers[0].ProductCode | Should -Be 'Updated.user.Product'
      $Installers[0].ElevationRequirement | Should -Be 'elevationProhibited'
      $Installers[1].ProductCode | Should -Be 'Updated.machine.Product'
      $Installers[1].ElevationRequirement | Should -Be 'elevationRequired'
    }

    It 'Does not add an elevation requirement that was not authored' {
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'wix'
        ProductCode   = '{OLD-PRODUCT}'
      }
      $Metadata = [ordered]@{
        ProductCode          = '{NEW-PRODUCT}'
        ElevationRequirement = 'elevationRequired'
      }

      Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -Metadata $Metadata -ParserName 'Windows Installer' -DiagnosticCollection ([Collections.Generic.List[object]]::new())

      $Installer.ProductCode | Should -Be '{NEW-PRODUCT}'
      $Installer.Contains('ElevationRequirement') | Should -BeFalse
    }

    It 'Updates NSIS ProductCode and AppsAndFeaturesEntries from one parser result' {
      Mock Get-WinGetInstallerAnalysis { throw 'The analyzer should not run after a successful declared parser' }
      Mock Get-NSISInfo {
        param($Path, $Architecture)
        $Architecture | Should -Be 'x64'
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
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter { $Architecture -eq 'x64' }
      Should -Invoke Get-WinGetInstallerAnalysis -Exactly 0
    }

    It 'Uses each installer entry architecture when one NSIS URL exposes different ProductCodes' {
      Mock Get-WinGetInstallerAnalysis { throw 'The analyzer should not run after a successful declared parser' }
      Mock Get-NSISInfo {
        param($Path, $Architecture)
        [pscustomobject]@{
          InstallerType              = 'Nullsoft'
          ProductCode                = $Architecture -eq 'x64' ? 'BitComet_x64' : 'BitComet'
          DisplayName                = 'BitComet 2.21'
          DisplayVersion             = '2.21'
          Publisher                  = 'CometNetwork'
          WritesAppsAndFeaturesEntry = $true
          Diagnostics                = @()
        }
      }

      $Results = foreach ($Architecture in @('x86', 'x64')) {
        $Installer = [ordered]@{
          Architecture  = $Architecture
          InstallerType = 'nullsoft'
          InstallerUrl  = $Script:InstallerUrl
          ProductCode   = 'Old.ProductCode'
        }
        Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger
      }

      $Results[0].ProductCode | Should -Be 'BitComet'
      $Results[1].ProductCode | Should -Be 'BitComet_x64'
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter { $Architecture -eq 'x86' }
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter { $Architecture -eq 'x64' }
    }

    It 'Uses each installer entry scope when one NSIS URL exposes different ProductCodes' {
      Mock Get-WinGetInstallerAnalysis { throw 'The analyzer should not run after a successful declared parser' }
      Mock Get-NSISInfo {
        param($Path, $Architecture, $Scope)
        [pscustomobject]@{
          InstallerType              = 'Nullsoft'
          ProductCode                = $Scope -eq 'user' ? 'DBeaver (current user)' : 'DBeaver'
          DisplayName                = $Scope -eq 'user' ? 'DBeaver 26.1.3 (current user)' : 'DBeaver 26.1.3'
          DisplayVersion             = '26.1.3'
          Publisher                  = 'DBeaver Corp'
          Scope                      = $Scope
          WritesAppsAndFeaturesEntry = $true
          Diagnostics                = @()
        }
      }

      $Results = foreach ($Scope in @('user', 'machine')) {
        $Installer = [ordered]@{
          Architecture  = 'x64'
          InstallerType = 'nullsoft'
          Scope         = $Scope
          InstallerUrl  = $Script:InstallerUrl
          ProductCode   = 'Old.ProductCode'
        }
        Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger
      }

      $Results[0].ProductCode | Should -Be 'DBeaver (current user)'
      $Results[1].ProductCode | Should -Be 'DBeaver'
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter { $Scope -eq 'user' }
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter { $Scope -eq 'machine' }
    }

    It 'Passes authored NSIS custom switches through the virtual silent command line' {
      Mock Get-WinGetInstallerAnalysis { throw 'The analyzer should not run after a successful declared parser' }
      Mock Get-NSISInfo {
        param($Path, $Architecture, $Scope, $CommandLine)
        [pscustomobject]@{
          InstallerType              = 'Nullsoft'
          ProductCode                = 'MultiCommander x64'
          DisplayName                = 'MultiCommander (x64)'
          DisplayVersion             = '16.2.0.3205'
          Publisher                  = 'Mathias Svensson'
          Scope                      = $Scope
          WritesAppsAndFeaturesEntry = $true
          Diagnostics                = @()
        }
      }
      $Installer = [ordered]@{
        Architecture      = 'x64'
        InstallerType     = 'nullsoft'
        Scope             = 'user'
        InstallerSwitches = [ordered]@{ Custom = '/InstallMode=User' }
        InstallerUrl      = $Script:InstallerUrl
        ProductCode       = 'MultiCommander x64'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'MultiCommander x64'
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter {
        $Scope -eq 'user' -and $CommandLine -match '^".+" /S /InstallMode=User$'
      }
    }

    It 'Does not reuse same-URL NSIS metadata across different scopes' {
      Mock Get-WinGetInstallerAnalysis { throw 'The analyzer should not run after a successful declared parser' }
      Mock Get-NSISInfo {
        param($Path, $Architecture, $Scope)
        [pscustomobject]@{
          InstallerType              = 'Nullsoft'
          ProductCode                = $Scope -eq 'user' ? 'DBeaver (current user)' : 'DBeaver'
          DisplayName                = $Scope -eq 'user' ? 'DBeaver 26.1.3 (current user)' : 'DBeaver 26.1.3'
          DisplayVersion             = '26.1.3'
          Publisher                  = 'DBeaver Corp'
          WritesAppsAndFeaturesEntry = $true
          Diagnostics                = @()
        }
      }
      $OldInstallers = @(
        [ordered]@{ Architecture = 'x64'; InstallerType = 'nullsoft'; Scope = 'user'; InstallerUrl = 'https://example.test/old.exe'; ProductCode = 'Old.User' },
        [ordered]@{ Architecture = 'x64'; InstallerType = 'nullsoft'; Scope = 'machine'; InstallerUrl = 'https://example.test/old.exe'; ProductCode = 'Old.Machine' }
      )
      $InstallerEntries = @(
        [ordered]@{ Architecture = 'x64'; Scope = 'user'; InstallerUrl = $Script:InstallerUrl },
        [ordered]@{ Architecture = 'x64'; Scope = 'machine'; InstallerUrl = $Script:InstallerUrl }
      )

      $Results = Update-WinGetInstallerManifestInstallers -OldInstallers $OldInstallers -InstallerEntries $InstallerEntries -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Results[0].ProductCode | Should -Be 'DBeaver (current user)'
      $Results[1].ProductCode | Should -Be 'DBeaver'
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter { $Scope -eq 'user' }
      Should -Invoke Get-NSISInfo -Exactly 1 -ParameterFilter { $Scope -eq 'machine' }
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
      ($Script:LogMessages.Message -join "`n") | Should -Match 'Inno Setup reports that the outer installer does not write a visible Apps & Features entry'
      Should -Invoke Get-InnoInfo -Exactly 1
    }

    It 'Preserves existing ARP metadata for a source-backed NSIS nested-payload wrapper' {
      Mock Get-NSISInfo {
        [pscustomobject]@{
          InstallerType                 = 'Nullsoft'
          WritesAppsAndFeaturesEntry    = $false
          DelegatesAppsAndFeaturesEntry = $true
          ExtractedFiles                = @('$PLUGINSDIR\setup.exe')
          Diagnostics                   = @(
            New-InstallerDiagnostic -Id 'NSIS.NestedPayload.ArpOwner' -Source NSIS -Message 'Nested installer owns ARP registration' -Kind Risk -Areas Metadata, Installability -AffectedFields ProductCode, AppsAndFeaturesEntries
          )
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
      $Script:LogMessages.Message | Should -Contain '[NSIS.NestedPayload.ArpOwner] NSIS: Nested installer owns ARP registration'
      ($Script:LogMessages.Message -join "`n") | Should -Match 'NSIS reports that the outer installer does not write a visible Apps & Features entry'
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
          DisplayName                  = 'New MSI Product'
          DisplayVersion               = '2.0.0'
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
          DisplayName                  = 'New MSI Product'
          DisplayVersion               = '2.0.0'
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
          DisplayName                  = 'WiX Product'
          DisplayVersion               = '2.0.0'
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
          DisplayName                  = 'Nested WiX Product'
          DisplayVersion               = '2.0.0'
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
          DisplayName                  = 'draw.io'
          DisplayVersion               = '30.3.6'
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

    It 'Preserves inherited AppX identity fields on WiX entries without parser warnings' {
      $Installer = [ordered]@{
        Architecture      = 'x64'
        InstallerType     = 'wix'
        ProductCode       = '{OLD-WIX-PRODUCT}'
        PackageFamilyName = 'MicrosoftCorporationII.WindowsSubsystemForLinux_8wekyb3d8bbwe'
        MinimumOSVersion  = '10.0.19041.0'
        Platform          = @('Windows.Desktop')
      }
      $Metadata = [ordered]@{
        ProductCode = '{NEW-WIX-PRODUCT}'
      }

      Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -Metadata $Metadata -ParserName 'Windows Installer' -DiagnosticCollection ([Collections.Generic.List[object]]::new())

      $Installer.ProductCode | Should -Be '{NEW-WIX-PRODUCT}'
      $Installer.PackageFamilyName | Should -Be 'MicrosoftCorporationII.WindowsSubsystemForLinux_8wekyb3d8bbwe'
      $Installer.MinimumOSVersion | Should -Be '10.0.19041.0'
      $Installer.Platform | Should -Be @('Windows.Desktop')
      $Messages = @($Script:LogMessages | ForEach-Object Message)
      $Messages | Should -Not -Contain "Windows Installer did not return a value for existing installer field 'PackageFamilyName'"
      $Messages | Should -Not -Contain "Windows Installer did not return a value for existing installer field 'MinimumOSVersion'"
      $Messages | Should -Not -Contain "Windows Installer did not return a value for existing installer field 'Platform'"
    }

    It 'Materializes an EXE ARP type for a Velopack MSI custom uninstall key' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                   = '{NEW-TOWER-MSI}'
          DisplayName                   = 'Tower'
          DisplayVersion                = '13.1.576.0'
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
          DisplayName      = 'MSI Product'
          DisplayVersion   = '1.0.0'
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
      Mock Get-WinGetInstallerAnalysis { $null }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'nullsoft'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Old.NSIS.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Old.NSIS.Product'
      ($Script:LogMessages.Message -join "`n") | Should -Match "Failed to parse metadata from the manifest-declared 'nullsoft' installer: The NSIS installer header could not be located"
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message | Should -Match 'nullsoft.ParserIncomplete'
    }

    It 'Treats a failed NSIS metadata parse as recoverable when structural evidence matches NSIS' {
      Mock Get-NSISInfo { throw 'Unsupported NSIS command layout' }
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          DetectedFileType = [pscustomobject]@{ Type = 'PE' }
          DetectedFamilies = @([pscustomobject]@{
              Family                  = 'NSIS/Nullsoft'
              Confidence              = 'high'
              ValidationStatus        = 'ConfirmedParser'
              MatchedMarkers          = @('DEADBEEF + NullsoftInst')
              SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'nullsoft' }
            })
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'nullsoft'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.NSIS.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.NSIS.Product'
      ($Script:LogMessages.Message -join "`n") | Should -Match "Failed to parse metadata from the manifest-declared 'nullsoft' installer: Unsupported NSIS command layout Structural evidence matches the declared family"
      $Script:LogMessages.Where({ $_.Level -eq 'Warning' }).Message | Should -Match 'nullsoft.ParserIncomplete'
    }

    It 'Does not treat a low-confidence CreateInstall candidate as an NSIS mismatch' {
      Mock Get-NSISInfo { throw 'Unsupported NSIS command layout' }
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{
          DetectedFileType   = [pscustomobject]@{ Type = 'PE' }
          DetectedFamilies   = @()
          RoutingHints       = @([pscustomobject]@{
              Family                  = 'CreateInstall'
              Confidence              = 'low'
              MatchedMarkers          = @('.ciq')
              SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'exe' }
            })
          RejectedCandidates = @([pscustomobject]@{
              Family           = 'CreateInstall'
              Confidence       = 'low'
              EvidenceKind     = 'Heuristic'
              ValidationStatus = 'RejectedByParser'
              IsOuterContainer = $false
            })
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'nullsoft'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = 'Existing.NSIS.Product'
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.ProductCode | Should -Be 'Existing.NSIS.Product'
      ($Script:LogMessages.Message -join "`n") | Should -Match "Failed to parse metadata from the manifest-declared 'nullsoft' installer: Unsupported NSIS command layout No high-confidence structural evidence"
    }

    It 'Throws when the declared parser positively identifies a different family' {
      Mock Get-InnoInfo {
        [pscustomobject]@{
          InstallerType              = 'Nullsoft'
          WritesAppsAndFeaturesEntry = $true
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'inno'
        InstallerUrl  = $Script:InstallerUrl
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw "*The manifest-declared 'inno' installer was detected as 'Nullsoft'*"
    }

    It 'Preserves fields when a manifest-declared MSIX installer cannot be parsed and its format is indeterminate' {
      Mock Get-MSIXInfo { throw 'The package is not a valid MSIX package' }
      Mock Get-WinGetInstallerAnalysis { $null }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'msix'
        InstallerUrl  = $Script:InstallerUrl
      }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger

      $Result.InstallerType | Should -Be 'msix'
      ($Script:LogMessages.Message -join "`n") | Should -Match "Failed to parse metadata from the manifest-declared 'msix' installer: The package is not a valid MSIX package"
    }

    It 'Throws when an HTML response is supplied for a manifest-declared Inno installer' {
      InModuleScope WinGetManifestUpdate {
        $Evidence = Get-WinGetDeclaredInstallerFormatEvidence -InstallerType inno -Analysis ([pscustomobject]@{
            DetectedFileType = [pscustomobject]@{ Type = 'HTMLDocument' }
            DetectedFamilies = @()
          })

        $Evidence.Status | Should -BeExactly 'NotMatched'
        $Evidence.DetectedInstallerType | Should -BeExactly 'HTML document'
        $Evidence.Evidence | Should -BeLike '*HTML response instead of an installer*'
      }
    }

    It 'Returns a uniform result shape with diagnostics for every known family' {
      Mock Get-MsiInstallerInfo { [pscustomobject]@{ ProductCode = '{P}'; InstallerBuilder = 'WiX'; Diagnostics = @() } }
      Mock Get-BurnInfo { [pscustomobject]@{ InstallerType = 'Burn'; ProductCode = '{B}'; Diagnostics = @() } }
      Mock Get-NSISInfo { [pscustomobject]@{ InstallerType = 'Nullsoft'; ProductCode = 'N'; DisplayName = 'N'; DisplayVersion = '1.0'; Diagnostics = @() } }
      Mock Get-InnoInfo { [pscustomobject]@{ InstallerType = 'Inno'; ProductCode = 'I'; Diagnostics = @() } }
      Mock Get-MSIXInfo { [pscustomobject]@{ InstallerType = 'msix'; Version = '1.0.0.0'; Diagnostics = @() } }

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
        $Info.PSObject.Properties.Name | Should -Contain 'Diagnostics'
        $Info.Diagnostics | Should -Be @()
      }
    }

    It 'Forwards Inno parser diagnostics like NSIS diagnostics' {
      Mock Get-InnoInfo {
        [pscustomobject]@{
          InstallerType              = 'Inno'
          ProductCode                = 'Inno.Product'
          DisplayName                = 'Inno Product'
          DisplayVersion             = '1.0.0'
          Publisher                  = 'Inno Publisher'
          WritesAppsAndFeaturesEntry = $true
          Diagnostics                = @(
            New-InstallerDiagnostic -Id 'Inno.Parser.Caveat' -Source Inno -Message 'Inno parser caveat' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode
          )
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
      $Script:LogMessages.Message | Should -Contain '[Inno.Parser.Caveat] Inno: Inno parser caveat'
    }

    It 'Logs identical parser diagnostics once across scope-specific installer entries' {
      Mock Get-NSISInfo {
        [pscustomobject]@{
          InstallerType              = 'Nullsoft'
          ProductCode                = $null
          WritesAppsAndFeaturesEntry = $false
          Diagnostics                = @(
            New-InstallerDiagnostic -Id 'NSIS.NestedPayload.Warning' -Source NSIS -Message 'Nested payload warning' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode
          )
        }
      }
      $OldInstallers = @(
        [ordered]@{
          Architecture  = 'x64'
          InstallerType = 'nullsoft'
          InstallerUrl  = $Script:InstallerUrl
          Scope         = 'user'
          ProductCode   = 'Existing.Product'
        }
        [ordered]@{
          Architecture  = 'x64'
          InstallerType = 'nullsoft'
          InstallerUrl  = $Script:InstallerUrl
          Scope         = 'machine'
          ProductCode   = 'Existing.Product'
        }
      )
      $InstallerEntries = @([ordered]@{
          Architecture = 'x64'
          InstallerUrl = $Script:InstallerUrl
        })

      $Result = @(Update-WinGetInstallerManifestInstallers -OldInstallers $OldInstallers -InstallerEntries $InstallerEntries -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger)

      $Result.Count | Should -Be 2
      @($Script:LogMessages.Where({ $_.Message -ceq '[NSIS.NestedPayload.Warning] NSIS: Nested payload warning' })).Count | Should -Be 1
      @($Script:LogMessages.Where({ $_.Message -like '*NSIS reports that the outer installer does not write a visible Apps & Features entry*' })).Count | Should -Be 1
      @($Script:LogMessages.Where({ $_.Level -ceq 'Verbose' -and $_.Message -like 'Updating installer #*' })).Count | Should -Be 2
      Should -Invoke Get-NSISInfo -Exactly 2
    }

    It 'Throws on a cross-major-type mismatch between script installer families' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = 'NSIS/Nullsoft'; Confidence = 'high'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'nullsoft' } }) }
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
        [pscustomobject]@{
          DetectedFileType = [pscustomobject]@{ Type = 'PE' }
          FamilyCandidates = @([pscustomobject]@{ Family = '7z SFX'; Confidence = 'medium'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'exe' } })
        }
      }
      $Installer = [ordered]@{
        Architecture  = 'x64'
        InstallerType = 'msi'
        InstallerUrl  = $Script:InstallerUrl
        ProductCode   = '{OLD-PRODUCT}'
      }

      { Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ($Installer | Copy-Object) -InstallerEntry ([ordered]@{}) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } |
        Should -Throw "*The manifest-declared 'msi' installer was detected as 'exe'*"
    }

    It 'Updates resolved fields while preserving an unmatched AppsAndFeaturesEntries item' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          ProductCode                  = '{NEW-PRODUCT}'
          DisplayName                  = 'WiX Product'
          DisplayVersion               = '2.0.0'
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

      # Resolved top-level metadata is updated independently from the ARP entry
      # whose identity could not be correlated.
      $Result.ProductCode | Should -Be '{NEW-PRODUCT}'
      $Result.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{OTHER-UPGRADE}'
      $Result.AppsAndFeaturesEntries[1].UpgradeCode | Should -Be '{THIRD-UPGRADE}'
      $Result.InstallerSha256 | Should -Not -BeNullOrEmpty
      $Result.InstallerSha256 | Should -Not -Be $OldSha256
      ($Script:LogMessages.Message -join "`n") | Should -Match 'Windows Installer metadata did not match any existing AppsAndFeaturesEntries item'
    }

    It 'Throws on a cross-major-type mismatch between Burn and WiX' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = 'MSI'; Confidence = 'high'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'wix' } }) }
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

    It 'Parses a plain MSI while keeping the compatible declared WiX type' {
      Mock Get-MsiInstallerInfo {
        [pscustomobject]@{
          InstallerType                = 'msi'
          ProductCode                  = '{NEW-PRODUCT}'
          DisplayName                  = 'MSI Product'
          DisplayVersion               = '2.0.0'
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
      ($Script:LogMessages.Message -join "`n") | Should -Match "The Windows Installer parser identified 'msi' while the manifest declares 'wix'; the declared type is retained"
    }

    It 'Throws when a manifest-declared MSIX installer is detected as another type' {
      Mock Get-WinGetInstallerAnalysis {
        [pscustomobject]@{ FamilyCandidates = @([pscustomobject]@{ Family = 'MSI'; Confidence = 'high'; SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'msi' } }) }
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
          DisplayName                   = 'Inconclusive WiX Product'
          DisplayVersion                = '1.0.0'
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
          DisplayName                   = 'WiX Product'
          DisplayVersion                = '1.0.0'
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
  }
}
