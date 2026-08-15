. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeDiscovery {
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'MSI.psm1') -Force
}

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  $Script:FixtureDirectory = $TestDrive

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url
  }
}

Describe 'MSI Apps & Features parser' {
  It 'Should distinguish the Tower Velopack MSI code from its visible EXE-style ARP key' {
    $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Tower-13.1.576.msi') -Uri 'https://www.git-tower.com/apps/tower3-win/576-01812649/Tower-13.1.576.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{4CA4189D-43E0-43C0-B1C5-6252F565CE71}'
    $Info.UpgradeCode | Should -Be '{871FD9D0-41D3-52BE-AF69-12F8B08740C0}'
    $Info.InstallerBuilder | Should -Be 'WiX'
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeTrue
    $Info.HasCustomAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesInstallerType | Should -Be 'exe'
    $Info.AppsAndFeaturesProductCode | Should -Be 'MSI:Tower'
    $Info.AppsAndFeaturesEntries.CustomAppsAndFeaturesRegistryKey | Should -Be 'Software\Microsoft\Windows\CurrentVersion\Uninstall\MSI:Tower'
  }

  It 'Should expose the unified parser contract properties' {
    $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Tower-13.1.576.msi') -Uri 'https://www.git-tower.com/apps/tower3-win/576-01812649/Tower-13.1.576.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.PSObject.Properties.Name[0..13] | Should -Be @(
      'Path', 'InstallerType', 'ProductCode', 'UpgradeCode', 'DisplayName', 'DisplayVersion',
      'Publisher', 'Scope', 'DefaultInstallLocation', 'WritesAppsAndFeaturesEntry',
      'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType', 'Warnings', 'UnresolvedFields'
    )
    $Info.PSObject.Properties.Name | Should -Not -Contain 'ProductName'
    $Info.PSObject.Properties.Name | Should -Not -Contain 'ProductVersion'
    $Info.PSObject.Properties.Name | Should -Contain 'Path'
    $Info.DisplayName | Should -Not -BeNullOrEmpty
    $Info.DisplayVersion | Should -Not -BeNullOrEmpty
    $Info.PSObject.Properties.Name | Should -Contain 'Scope'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.Warnings | Should -Be @()
    $Info.UnresolvedFields | Should -Be @()
    $Info.Warnings.GetType() | Should -Be ([string[]])
    $Info.UnresolvedFields.GetType() | Should -Be ([string[]])
  }

  It 'Should detect Figma MSI writing a hidden native ARP entry and visible .msq ARP entry' {
    $Fixture = Get-InstallerFixture -Name 'Figma-125.8.5.msi' -Url 'https://desktop.figma.com/win/build/Figma-125.8.5.msi'
    $Info = Get-MsiAppsAndFeaturesInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{837EEE3D-E993-4C41-AD65-5FBAF82B9159}'
    $Info.AppsAndFeaturesProductCode | Should -Be '{837EEE3D-E993-4C41-AD65-5FBAF82B9159}.msq'
    $Info.HasMsqAppsAndFeaturesEntry | Should -BeTrue
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeTrue
    $Info.MsqAppsAndFeaturesRegistryKey | Should -Be 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{837EEE3D-E993-4C41-AD65-5FBAF82B9159}.msq'
    $Info.MsqAppsAndFeaturesRegistryRows.Name | Should -Contain 'DisplayName'
    $Info.MsqAppsAndFeaturesRegistryRows.Name | Should -Contain 'UninstallString'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'exe'
    $Info.AppsAndFeaturesWindowsInstaller | Should -BeFalse
    Test-MsiMsqAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
    Read-AppsAndFeaturesProductCodeFromMsi -Path $Fixture | Should -Be '{837EEE3D-E993-4C41-AD65-5FBAF82B9159}.msq'
  }

  It 'Should detect Tulip Player MSI writing a hidden native ARP entry and visible .msq ARP entry' {
    $Fixture = Get-InstallerFixture -Name 'Tulip Player Setup.msi' -Url 'https://download.tulip.co/releases/prod/win/Tulip%20Player%20Setup.msi'
    $Info = Get-MsiAppsAndFeaturesInfo -Path $Fixture

    $Info.ProductCode | Should -Match '^\{[0-9A-F-]{36}\}$'
    $Info.AppsAndFeaturesProductCode | Should -Be "$($Info.ProductCode).msq"
    $Info.HasMsqAppsAndFeaturesEntry | Should -BeTrue
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeTrue
    $Info.MsqAppsAndFeaturesRegistryKey | Should -Be "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($Info.ProductCode).msq"
    $Info.MsqAppsAndFeaturesRegistryRows.Name | Should -Contain 'DisplayName'
    $Info.MsqAppsAndFeaturesRegistryRows.Name | Should -Contain 'UninstallString'
    Test-MsiMsqAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
    Read-AppsAndFeaturesProductCodeFromMsi -Path $Fixture | Should -Be "$($Info.ProductCode).msq"
  }

  It 'Should keep the native ProductCode for a normal WiX MSI without the .msq ARP entry' {
    $Fixture = Get-InstallerFixture -Name 'draw.io-30.2.6.msi' -Url 'https://github.com/jgraph/drawio-desktop/releases/download/v30.2.6/draw.io-30.2.6.msi'
    $Info = Get-MsiAppsAndFeaturesInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{0D35F535-BFC3-482E-96D2-5B8FCE0A4E10}'
    $Info.InstallerType | Should -Be 'wix'
    $Info.AppsAndFeaturesProductCode | Should -Be '{0D35F535-BFC3-482E-96D2-5B8FCE0A4E10}'
    $Info.InstallerBuilder | Should -Be 'WiX'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'wix'
    $Info.HasMsqAppsAndFeaturesEntry | Should -BeFalse
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeFalse
    $Info.MsqAppsAndFeaturesRegistryKey | Should -BeNullOrEmpty
    Test-MsiMsqAppsAndFeaturesEntry -Path $Fixture | Should -BeFalse
    Read-AppsAndFeaturesProductCodeFromMsi -Path $Fixture | Should -Be '{0D35F535-BFC3-482E-96D2-5B8FCE0A4E10}'
  }
}

Describe 'MSI builder and install-location parser' {
  InModuleScope MSI {
    It 'Should distinguish InstallScript MSI from Basic MSI using compiled database markers' {
      $InstallScriptMsi = [pscustomobject]@{
        Properties       = @{}
        Tables           = @('Property', 'ISComponentExtended')
        CustomActionRows = @([pscustomobject]@{ Action = 'ISVerifyScriptingRuntime' })
        SummaryInfo      = [pscustomobject]@{ CreatingApp = 'InstallShield'; Comments = $null }
      }
      $BasicMsi = [pscustomobject]@{
        Properties       = @{}
        Tables           = @('Property', 'ISComponentExtended', 'ISSetupType')
        CustomActionRows = @([pscustomobject]@{ Action = 'ISPreventDowngrade' })
        SummaryInfo      = [pscustomobject]@{ CreatingApp = 'InstallShield'; Comments = $null }
      }

      $InstallScriptResult = Get-MsiInstallShieldProjectTypeFromStaticTableInfo -StaticTableInfo $InstallScriptMsi
      $BasicResult = Get-MsiInstallShieldProjectTypeFromStaticTableInfo -StaticTableInfo $BasicMsi

      $InstallScriptResult.ProjectType | Should -Be 'InstallScript MSI'
      $InstallScriptResult.CustomActions | Should -Be @('ISVerifyScriptingRuntime')
      $BasicResult.ProjectType | Should -Be 'Basic MSI'
      $BasicResult.CustomActions | Should -BeNullOrEmpty
    }

    It 'Should retain InstallScript MSI sequence conditions without evaluating them' {
      $StaticTableInfo = [pscustomobject]@{
        Properties       = @{}
        Tables           = @('Property', 'CustomAction', 'InstallExecuteSequence')
        SummaryInfo      = [pscustomobject]@{ CreatingApp = 'InstallShield'; Comments = $null }
        CustomActionRows = @(
          [pscustomobject]@{ Action = 'ISVerifyScriptingRuntime'; Type = 1; Source = 'ISSetup.dll'; Target = 'VerifyScriptingRuntime' },
          [pscustomobject]@{ Action = 'ISInstallScriptStartup'; Type = 1; Source = 'ISSetup.dll'; Target = 'InstallScriptStartup' }
        )
        SequenceRows     = @(
          [pscustomobject]@{ Table = 'InstallExecuteSequence'; Action = 'ISVerifyScriptingRuntime'; Condition = 'VersionNT'; Sequence = 100 },
          [pscustomobject]@{ Table = 'InstallExecuteSequence'; Action = 'ISInstallScriptStartup'; Condition = 'NOT Installed'; Sequence = 110 }
        )
      }

      $Actions = Get-MsiInstallShieldScriptActionInfo -StaticTableInfo $StaticTableInfo
      $Actions.Action | Should -Be @('ISInstallScriptStartup', 'ISVerifyScriptingRuntime')
      ($Actions | Where-Object Action -EQ 'ISInstallScriptStartup').Sequences.Condition | Should -Be 'NOT Installed'
      ($Actions | Where-Object Action -EQ 'ISInstallScriptStartup').Scheduled | Should -BeTrue
    }

    It 'Should expose Basic MSI compiled InstallScript actions without changing project type' {
      $StaticTableInfo = [pscustomobject]@{
        Properties       = @{}
        Tables           = @('Property', 'Binary', 'CustomAction', 'InstallExecuteSequence')
        SummaryInfo      = [pscustomobject]@{ CreatingApp = 'InstallShield'; Comments = $null }
        CustomActionRows = @([pscustomobject]@{
            Action = 'ConfigureProduct'; Type = 1; Source = 'ISSetup.dll'; Target = 'f1'
          })
        SequenceRows     = @([pscustomobject]@{
            Table = 'InstallExecuteSequence'; Action = 'ConfigureProduct'; Condition = 'NOT Installed'; Sequence = 1200
          })
      }

      $ProjectType = Get-MsiInstallShieldProjectTypeFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $Actions = Get-MsiInstallShieldScriptActionInfo -StaticTableInfo $StaticTableInfo -ProjectTypeInfo $ProjectType

      $ProjectType.ProjectType | Should -Be 'Basic MSI'
      $Actions.Action | Should -Be 'ConfigureProduct'
      $Actions.Kind | Should -Be 'CompiledFunction'
      $Actions.Target | Should -Be 'f1'
      $Actions.Sequences.Condition | Should -Be 'NOT Installed'
    }

    It 'Should distinguish the InstallScript MSI Setup.exe contract from compiled-script evidence' {
      $ProjectType = [pscustomobject]@{ ProjectType = 'InstallScript MSI' }
      $Actions = @([pscustomobject]@{
          Action    = 'ISVerifyScriptingRuntime'
          Sequences = @([pscustomobject]@{
              Table     = 'InstallUISequence'
              Sequence  = 100
              Condition = 'NOT AFTERREBOOT AND NOT ISSETUPDRIVEN'
            })
        })

      $Requirement = Get-MsiInstallShieldLauncherRequirement -ProjectTypeInfo $ProjectType -ScriptActions $Actions

      $Requirement.IsApplicable | Should -BeTrue
      $Requirement.RequiresSetupExe | Should -BeTrue
      $Requirement.VerifierAction.Action | Should -Be 'ISVerifyScriptingRuntime'
      $Requirement.SequenceConditions | Should -Be 'NOT AFTERREBOOT AND NOT ISSETUPDRIVEN'
      $Requirement.Evidence | Should -Contain 'ISVerifyScriptingRuntime custom action'
      $Requirement.Warnings | Should -BeNullOrEmpty
    }

    It 'Should classify Chromium enterprise MSIs compiled from WiX source' {
      $StaticTableInfo = [pscustomobject]@{
        Properties       = @{}
        Tables           = @('Property', 'Binary', 'CustomAction')
        CustomActionRows = @(
          [pscustomobject]@{ Action = 'SetProductTagProperty'; Source = 'ProductTag'; Target = 'appguid={APP-ID}' }
          [pscustomobject]@{ Action = 'BuildInstallCommand'; Source = 'InstallCommand'; Target = '--silent --install' }
          [pscustomobject]@{ Action = 'ExtractTagInfoFromInstaller'; Source = 'MsiInstallerCustomActionDll'; Target = 'ExtractTagInfoFromInstaller' }
          [pscustomobject]@{ Action = 'DoInstall'; Source = 'GoogleChromeInstaller'; Target = '[InstallCommand]' }
        )
        SummaryInfo      = [pscustomobject]@{ CreatingApp = $null; Comments = $null }
      }

      Get-MsiBuilderFromStaticTableInfo -StaticTableInfo $StaticTableInfo | Should -Be 'WiX'
    }

    It 'Should classify the MSI Program Name exposed by DTF as CreatingApp' {
      $StaticTableInfo = [pscustomobject]@{
        Properties          = @{}
        Tables              = @('Property')
        CustomActionRows    = @()
        UpgradeRows         = @()
        LaunchConditionRows = @()
        SummaryInfo         = [pscustomobject]@{
          CreatingApp = 'Windows Installer XML Toolset (3.11.2.4516)'
          Comments    = $null
        }
      }

      Get-MsiBuilderFromStaticTableInfo -StaticTableInfo $StaticTableInfo | Should -Be 'WiX'
    }

    It 'Should read an exact Advanced Installer builder version only from Summary Information' {
      $StaticTableInfo = [pscustomobject]@{
        Properties          = @{ ProductVersion = '99.1.2' }
        Tables              = @('Property', 'AI_ThemeStyle')
        CustomActionRows    = @()
        UpgradeRows         = @()
        LaunchConditionRows = @()
        SummaryInfo         = [pscustomobject]@{
          CreatingApp = 'Advanced Installer 10.3'
          Comments    = $null
        }
      }

      $Builder = Get-MsiBuilderFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $VersionInfo = Get-MsiInstallerBuilderVersionInfo -StaticTableInfo $StaticTableInfo -InstallerBuilder $Builder

      $Builder | Should -Be 'AdvancedInstaller'
      $VersionInfo.Version | Should -Be '10.3'
      $VersionInfo.Source | Should -Be 'SummaryInformation.CreatingApp'

      $StaticTableInfo.SummaryInfo.CreatingApp = 'A publisher-customized creating application'
      $VersionInfo = Get-MsiInstallerBuilderVersionInfo -StaticTableInfo $StaticTableInfo -InstallerBuilder $Builder
      $VersionInfo.Version | Should -BeNullOrEmpty
      $VersionInfo.Source | Should -BeNullOrEmpty
    }

    It 'Should not treat the ordinary IsLight property as InstallShield before WixSharp evidence' {
      $StaticTableInfo = [pscustomobject]@{
        Properties          = @{
          IsLight                 = 'true'
          WixSharp_InstallDialogs = 'WixSharpSetup, Version=1.0.0.0|Example.Dialogs'
        }
        Tables              = @('Property', 'CustomAction', 'MsiEmbeddedUI')
        CustomActionRows    = @([pscustomobject]@{
            Action = 'WixSharp_InitRuntime_Action'
            Source = 'WixSharp_InitRuntime_Action_File'
            Target = 'WixSharp_InitRuntime_Action'
          })
        UpgradeRows         = @()
        LaunchConditionRows = @()
        SummaryInfo         = [pscustomobject]@{ CreatingApp = $null; Comments = $null }
      }

      Get-MsiBuilderFromStaticTableInfo -StaticTableInfo $StaticTableInfo | Should -Be 'WiX'
    }
  }

  It 'Should read Extension, ProgId, and Verb table associations from draw.io' {
    $Fixture = Get-InstallerFixture -Name 'draw.io-30.2.6.msi' -Url 'https://github.com/jgraph/drawio-desktop/releases/download/v30.2.6/draw.io-30.2.6.msi'
    $Info = Get-MsiAssociationInfo -Path $Fixture

    $Info.Protocols | Should -BeNullOrEmpty
    $Info.FileExtensions | Should -Be @('drawio', 'mermaid', 'mmd', 'vsdx')
    ($Info.FileExtensionAssociations | Where-Object FileExtension -EQ 'drawio').DefaultProgId | Should -Be 'draw.io.drawio'
    ($Info.FileExtensionAssociations | Where-Object FileExtension -EQ 'drawio').Command | Should -Be 'Open with draw.io'
    Read-FileExtensionsFromMsi -Path $Fixture | Should -Be @('drawio', 'mermaid', 'mmd', 'vsdx')
  }

  It 'Should classify an Advanced Installer MSI with a custom EXE-style ARP entry' {
    $Fixture = Get-InstallerFixture -Name 'Vurbo.ai_1.12.2.2.msi' -Url 'https://ipevo-software.s3.us-east-1.amazonaws.com/Vurbo/Windows/Vurbo.ai_1.12.2.2.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'AdvancedInstaller'
    $Info.InstallerType | Should -Be 'msi'
    $Info.AllUsers | Should -Be '1'
    $Info.InstallLocationProperty | Should -Be 'APPDIR'
    $Info.InstallLocationSwitch | Should -Be 'APPDIR="<INSTALLPATH>"'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'exe'
    $Info.AppsAndFeaturesProductCode | Should -Be 'Vurbo.ai 1.12.2.2'
    $Info.HasCustomAppsAndFeaturesEntry | Should -BeTrue
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeTrue
    Read-InstallerBuilderFromMsi -Path $Fixture | Should -Be 'AdvancedInstaller'
    Read-InstallLocationPropertyFromMsi -Path $Fixture | Should -Be 'APPDIR'
    Read-InstallLocationSwitchFromMsi -Path $Fixture | Should -Be 'APPDIR="<INSTALLPATH>"'
    Read-AppsAndFeaturesInstallerTypeFromMsi -Path $Fixture | Should -Be 'exe'
  }

  It 'Should classify an Advanced Installer MSI with a native MSI ARP entry' {
    $Fixture = Get-InstallerFixture -Name 'BoxDrive-2.51.234.msi' -Url 'https://e3.boxcdn.net/desktop/releases/win/BoxDrive-2.51.234.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'AdvancedInstaller'
    $Info.InstallLocationProperty | Should -Be 'APPDIR'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.AppsAndFeaturesProductCode | Should -Be '{F84F95F3-5AE8-4676-8BA2-F6294C8A7F5E}'
    $Info.HasCustomAppsAndFeaturesEntry | Should -BeFalse
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeFalse
    $Info.ElevationRequirement | Should -BeNullOrEmpty
    $Info.ElevationRequirementEvidence | Should -BeNullOrEmpty
    Read-AppsAndFeaturesInstallerTypeFromMsi -Path $Fixture | Should -Be 'msi'
  }

  It 'Should read the exact builder version from the current official Advanced Installer MSI' -Tag 'LargeFixture' {
    $Name = 'AdvancedInstaller-23.9.msi'
    $Url = 'https://storage.advancedupdater.cloud/downloads/23.9/advinst.msi'
    $Sha256 = '07526888339024CA944CF5053AB57D9454DD9470DA5AAAB91766DCFCAA5E16C8'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name)
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      if ($env:DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES -eq '1') {
        $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url -Sha256 $Sha256
      } else {
        Set-ItResult -Skipped -Because 'Set DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES=1 to cache the 312 MiB official Advanced Installer MSI.'
        return
      }
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'AdvancedInstaller'
    $Info.InstallerBuilderVersion | Should -Be '23.9'
    $Info.InstallerBuilderVersionSource | Should -Be 'SummaryInformation.CreatingApp'
    $Info.SummaryCreatingApplication | Should -Be 'Advanced Installer 23.9'
  }

  It 'Should read explicit builder provenance at the Advanced Installer <Version> boundary' -ForEach @(
    @{ Version = '6.4'; Sha256 = '72A5D349F6E97AF59EECE121BA12E5F69E333FEBE06381D072022B241F0E7028' }
    @{ Version = '8.6'; Sha256 = '0A99BE66E6C08DC6E48BFE94958F0A998BEB5BF5E9CE6F52B17092123A1B5336' }
  ) {
    $Name = "AdvancedInstaller-$Version.msi"
    $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri "https://storage.advancedupdater.cloud/downloads/$Version/advinst.msi" -Sha256 $Sha256
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'AdvancedInstaller'
    $Info.InstallerBuilderVersion | Should -Be $Version
    $Info.InstallerBuilderVersionSource | Should -Be 'SummaryInformation.CreatingApp'
    $Info.SummaryCreatingApplication | Should -Be "Advanced Installer $Version"
  }

  It 'Should classify an InstallShield-authored MSI and read INSTALLDIR' {
    $Fixture = Get-InstallerFixture -Name 'ProjectViewer_365_PC_26.4.1290.msi' -Url 'https://projectviewercentral.com/download/ProjectViewerPC/365/26/ProjectViewer_365_PC_26.4.1290.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'InstallShield'
    $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
    $Info.InstallLocationProperty | Should -Be 'INSTALLDIR'
    $Info.InstallLocationSwitch | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.AppsAndFeaturesProductCode | Should -Be '{60D8268A-3889-416D-8274-BF37D5CEE764}'
  }

  It 'Should classify WiX MSIs and read their install-location variables' {
    $Figma = Get-InstallerFixture -Name 'Figma-125.8.5.msi' -Url 'https://desktop.figma.com/win/build/Figma-125.8.5.msi'
    $Draw = Get-InstallerFixture -Name 'draw.io-30.2.6.msi' -Url 'https://github.com/jgraph/drawio-desktop/releases/download/v30.2.6/draw.io-30.2.6.msi'

    $FigmaInfo = Get-MsiInstallerInfo -Path $Figma
    $DrawInfo = Get-MsiInstallerInfo -Path $Draw

    $FigmaInfo.InstallerBuilder | Should -Be 'WiX'
    $FigmaInfo.InstallerType | Should -Be 'wix'
    $FigmaInfo.AllUsers | Should -Be '2'
    $FigmaInfo.InstallLocationProperty | Should -Be 'APPLICATIONROOTDIRECTORY'
    $FigmaInfo.AppsAndFeaturesInstallerType | Should -Be 'exe'
    $DrawInfo.InstallerBuilder | Should -Be 'WiX'
    $DrawInfo.InstallLocationProperty | Should -Be 'APPLICATIONFOLDER'
    $DrawInfo.InstallLocationSource | Should -Be 'WIXUI_INSTALLDIR'
  }

  It 'Should classify the current ScreenToGif WixSharp MSI as WiX' {
    $Fixture = Get-InstallerFixture -Name 'ScreenToGif-2.43.2-x64.msi' -Url 'https://github.com/NickeManarin/ScreenToGif/releases/download/2.43.2/ScreenToGif.2.43.2.Light.Setup.x64.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'WiX'
    $Info.InstallerType | Should -Be 'wix'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'wix'
    $Info.InstallLocationProperty | Should -Be 'INSTALLDIR'
  }

  It 'Should classify Belgian eID Viewer from its WiX Summary Information Program Name' {
    $Fixture = Get-InstallerFixture -Name 'BeidViewer-5.1.31.6342.msi' -Url 'https://eid.belgium.be/sites/default/files/software/BeidViewer%205.1.31.6342.msi'
    (Get-FileHash -Path $Fixture -Algorithm SHA256).Hash | Should -Be '6780CE11049E29FA25A2BEE0377CFABBDAC048B61258989DFDB610EBF649DAA9'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'WiX'
    $Info.InstallerType | Should -Be 'wix'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'wix'
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeFalse
    $Info.HasCustomAppsAndFeaturesEntry | Should -BeFalse
  }
}

Describe 'MSI package architecture parser' {
  InModuleScope MSI {
    It 'Should map an omitted Summary Information platform to x86' {
      Convert-MsiTemplatePlatformToPackageArchitecture -Template ';1033' | Should -Be 'x86'
    }

    It 'Should map explicit Summary Information platforms' -ForEach @(
      @{ Template = 'Intel;1033'; Expected = 'x86' }
      @{ Template = 'x64;1033'; Expected = 'x64' }
      @{ Template = 'Intel64;1033'; Expected = 'x64' }
      @{ Template = 'Arm64;1033'; Expected = 'arm64' }
    ) {
      Convert-MsiTemplatePlatformToPackageArchitecture -Template $Template | Should -Be $Expected
    }
  }
}

Describe 'MSI elevation requirement parser' {
  InModuleScope MSI {
    It 'Should require explicit MSI elevation evidence rather than machine metadata alone' {
      $StaticTableInfo = [pscustomobject]@{
        Properties          = @{ ALLUSERS = '1' }
        LaunchConditionRows = @()
        CustomActionRows    = @()
        SequenceRows        = @()
        SummaryInfo         = [pscustomobject]@{ WordCount = 2 }
      }

      $Result = Get-MsiElevationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo

      $Result.ElevationRequirement | Should -BeNullOrEmpty
      $Result.AllowsInstallWithoutElevation | Should -BeFalse
      $Result.Evidence | Should -BeNullOrEmpty
    }

    It 'Should detect authored elevation launch conditions' {
      $StaticTableInfo = [pscustomobject]@{
        LaunchConditionRows = @([pscustomobject]@{
            Condition   = 'SCM_IS_ACCESSIBLE'
            Description = 'This installation requires elevated privileges. Please run it as an administrator.'
          })
        CustomActionRows    = @()
        SequenceRows        = @()
        SummaryInfo         = [pscustomobject]@{ WordCount = 2 }
      }

      $Result = Get-MsiElevationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo

      $Result.ElevationRequirement | Should -Be 'elevationRequired'
      $Result.Evidence.Kind | Should -Be 'LaunchCondition'
      $Result.Evidence.Confidence | Should -Be 'Explicit'
    }

    It 'Should detect Chromium product tags and scheduled restart-as-admin actions' {
      $StaticTableInfo = [pscustomobject]@{
        LaunchConditionRows = @()
        CustomActionRows    = @(
          [pscustomobject]@{ Action = 'SetProductTagProperty'; Type = 51; Source = 'ProductTag'; Target = 'appguid={ID}&needsAdmin=True' },
          [pscustomobject]@{ Action = 'RestartAsAdmin'; Type = 257; Source = 'Actions'; Target = 'RestartAsAdmin' }
        )
        SequenceRows        = @([pscustomobject]@{ Table = 'InstallExecuteSequence'; Action = 'RestartAsAdmin'; Condition = ''; Sequence = 57 })
        SummaryInfo         = [pscustomobject]@{ WordCount = 2 }
      }

      $Result = Get-MsiElevationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo

      $Result.ElevationRequirement | Should -Be 'elevationRequired'
      $Result.Evidence.Kind | Should -Be @('NestedInstallerProductTag', 'ElevationCustomAction')
    }

    It 'Should distinguish a vendor no-UI silent modifier from basic UI' {
      $StaticTableInfo = [pscustomobject]@{
        LaunchConditionRows = @()
        CustomActionRows    = @(
          [pscustomobject]@{ Action = 'SetProductTagProperty'; Type = 51; Source = 'ProductTag'; Target = 'appguid={ID}&needsAdmin=True' },
          [pscustomobject]@{ Action = 'BuildInstallCommand'; Type = 51; Source = 'InstallCommand'; Target = '--install="[ProductTag]"' },
          [pscustomobject]@{ Action = 'AppendSilent'; Type = 51; Source = 'InstallCommand'; Target = '[InstallCommand] --silent' },
          [pscustomobject]@{ Action = 'ExtractTagInfoFromInstaller'; Type = 1; Source = 'MsiInstallerCustomActionDll'; Target = 'ExtractTagInfoFromInstaller' },
          [pscustomobject]@{ Action = 'DoInstall'; Type = 3074; Source = 'NestedInstaller'; Target = '[InstallCommand]' }
        )
        SequenceRows        = @(
          [pscustomobject]@{ Table = 'InstallExecuteSequence'; Action = 'ExtractTagInfoFromInstaller'; Condition = 'NOT Installed'; Sequence = 100 },
          [pscustomobject]@{ Table = 'InstallExecuteSequence'; Action = 'AppendSilent'; Condition = 'NOT Installed AND (UILevel = 2)'; Sequence = 200 },
          [pscustomobject]@{ Table = 'InstallExecuteSequence'; Action = 'DoInstall'; Condition = 'NOT Installed'; Sequence = 300 }
        )
        SummaryInfo         = [pscustomobject]@{ WordCount = 2 }
      }

      $ChromiumInfo = Get-MsiChromiumEnterpriseInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $ElevationInfo = Get-MsiElevationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo -ChromiumEnterpriseInfo $ChromiumInfo

      $ChromiumInfo.IsDetected | Should -BeTrue
      $ChromiumInfo.IsSilentAtNoUi | Should -BeTrue
      $ChromiumInfo.IsSilentAtBasicUi | Should -BeFalse
      $ChromiumInfo.SilentElevationBehavior | Should -Be 'RequiresPreElevation'
      $ChromiumInfo.HasImmediateTagExtraction | Should -BeTrue
      $ChromiumInfo.DeferredInstallerAction.IsDeferred | Should -BeTrue
      $ChromiumInfo.DeferredInstallerAction.NoImpersonate | Should -BeTrue
      $ElevationInfo.Evidence.Kind | Should -Be 'ChromiumUpdaterSilentPreElevation'
    }

    It 'Should detect an early InstallShield context action only when non-elevated support is not declared' {
      $StaticTableInfo = [pscustomobject]@{
        LaunchConditionRows = @()
        CustomActionRows    = @([pscustomobject]@{ Action = 'ISSetAllUsers'; Type = 257; Source = 'SetAllUsers.dll'; Target = 'SetAllUsers' })
        SequenceRows        = @([pscustomobject]@{ Table = 'InstallExecuteSequence'; Action = 'ISSetAllUsers'; Condition = 'Not Installed'; Sequence = 10 })
        SummaryInfo         = [pscustomobject]@{ WordCount = 0 }
      }

      $Result = Get-MsiElevationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $StaticTableInfo.SummaryInfo.WordCount = 8
      $NonElevatedResult = Get-MsiElevationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo

      $Result.ElevationRequirement | Should -Be 'elevationRequired'
      $Result.Evidence.Kind | Should -Be 'InstallShieldEarlyContextAction'
      $Result.Evidence.Confidence | Should -Be 'Observed'
      $NonElevatedResult.ElevationRequirement | Should -BeNullOrEmpty
    }
  }

  It 'Should parse the distinct cached real-world elevation layouts' -ForEach @(
    @{ Name = 'CatoNetworks.CatoClient.x64.msi'; Kind = 'LaunchCondition' }
    @{ Name = 'Cribl.CriblEdge.x64.msi'; Kind = 'ElevationCustomAction' }
    @{ Name = 'Cisco.NetworkRecordingPlayer.x86.msi'; Kind = 'InstallShieldEarlyContextAction' }
    @{ Name = 'CrisisGo.CrisisGo.x86.msi'; Kind = 'InstallShieldEarlyContextAction' }
    @{ Name = 'PaloAltoNetworks.PrismaAccessBrowser.x64.msi'; Kind = 'ChromiumUpdaterSilentPreElevation' }
  ) {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name)
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because "The durable MSI elevation fixture '$Name' is not cached."
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.ElevationRequirement | Should -Be 'elevationRequired'
    $Info.ElevationRequirementEvidence.Kind | Should -Contain $Kind
    Read-ElevationRequirementFromMsi -Path $Fixture | Should -Be 'elevationRequired'
  }

  It 'Should model the untagged Chrome enterprise MSI as always-silent nested installation' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'GoogleChromeStandaloneEnterprise-current-x64.msi')
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The durable Google Chrome enterprise MSI fixture is not cached.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture
    $ChromiumInfo = $Info.ChromiumEnterpriseMsiInfo

    $ChromiumInfo.IsDetected | Should -BeTrue
    $ChromiumInfo.OuterTag.IsTagged | Should -BeFalse
    $ChromiumInfo.ProductTagSource | Should -Be 'DefaultProductTag'
    $ChromiumInfo.EffectiveNeedsAdmin | Should -Be 'True'
    $ChromiumInfo.IsSilentAtNoUi | Should -BeTrue
    $ChromiumInfo.IsSilentAtBasicUi | Should -BeTrue
    $ChromiumInfo.RequiresPreElevationForSilent | Should -BeTrue
    $Info.ElevationRequirementEvidence.Kind | Should -Contain 'ChromiumUpdaterSilentPreElevation'
  }

  It 'Should ignore the embedded Prisma tag and retain its no-UI-only silent modifier' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'PaloAltoNetworks.PrismaAccessBrowser.x64.msi')
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The durable Prisma Access Browser MSI fixture is not cached.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture
    $ChromiumInfo = $Info.ChromiumEnterpriseMsiInfo

    $ChromiumInfo.IsDetected | Should -BeTrue
    $ChromiumInfo.OuterTag.IsTagged | Should -BeFalse
    $ChromiumInfo.ProductTagSource | Should -Be 'DefaultProductTag'
    $ChromiumInfo.EffectiveNeedsAdmin | Should -Be 'True'
    $ChromiumInfo.IsSilentAtNoUi | Should -BeTrue
    $ChromiumInfo.IsSilentAtBasicUi | Should -BeFalse
    $ChromiumInfo.RequiresPreElevationForSilent | Should -BeTrue
    $ChromiumInfo.SilentModifierActions.Action | Should -Contain 'TalonAppendSilentToInstallCommand'
    $Info.ElevationRequirementEvidence.Kind | Should -Contain 'ChromiumUpdaterSilentPreElevation'
  }
}

Describe 'MSI condition evaluator' {
  InModuleScope MSI {
    It 'Should apply the documented logical precedence' {
      (Resolve-MsiConditionExpression -Condition '1 OR 0 AND 0').State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition '(1 OR 0) AND 0').State | Should -Be 'False'
      (Resolve-MsiConditionExpression -Condition '1 XOR 1').State | Should -Be 'False'
      (Resolve-MsiConditionExpression -Condition '1 EQV 1').State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition '1 IMP 0').State | Should -Be 'False'
      (Resolve-MsiConditionExpression -Condition '0 IMP MISSING').State | Should -Be 'True'
    }

    It 'Should preserve unknown runtime state through three-valued logic' {
      $Unknown = Resolve-MsiConditionExpression -Condition 'MISSING AND 1'
      $Unknown.State | Should -Be 'Unknown'
      $Unknown.IsComplete | Should -BeFalse
      $Unknown.UnknownSymbols | Should -Be 'MISSING'

      (Resolve-MsiConditionExpression -Condition 'MISSING AND 0').State | Should -Be 'False'
      (Resolve-MsiConditionExpression -Condition 'MISSING OR 1').State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition 'MISSING' -UnspecifiedSymbolState Absent).State | Should -Be 'False'
      (Resolve-MsiConditionExpression -Condition '' -UnspecifiedSymbolState Absent).State | Should -Be 'None'
    }

    It 'Should distinguish known property presence from a known property value' {
      $Present = Resolve-MsiConditionExpression -Condition 'VersionNT64 AND VersionNT64 >= 601' -KnownPresentProperty VersionNT64
      $Present.State | Should -Be 'Unknown'
      $Present.ReferencedSymbols[0].IsPresent | Should -BeTrue
      $Present.ReferencedSymbols[0].IsKnown | Should -BeFalse

      (Resolve-MsiConditionExpression -Condition 'NOT VersionNT64' -KnownAbsentProperty VersionNT64).State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition 'VALUE >= 10' -Property @{ VALUE = '11' }).State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition 'VALUE = 10' -Property @{ VALUE = 'not-a-number' }).State | Should -Be 'False'
      (Resolve-MsiConditionExpression -Condition 'VALUE <> 10' -Property @{ VALUE = 'not-a-number' }).State | Should -Be 'True'
    }

    It 'Should implement case-sensitive and tilde-prefixed string comparisons' {
      $Properties = @{ NAME = 'AlphaBeta'; PATCH = 'base.msp;update.msp' }
      (Resolve-MsiConditionExpression -Condition 'NAME = "alphabeta"' -Property $Properties).State | Should -Be 'False'
      (Resolve-MsiConditionExpression -Condition 'NAME ~= "alphabeta"' -Property $Properties).State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition 'NAME << "Alpha"' -Property $Properties).State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition 'NAME >> "Beta"' -Property $Properties).State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition 'PATCH >< "update.msp"' -Property $Properties).State | Should -Be 'True'
    }

    It 'Should implement numeric bitwise condition operators' {
      $Properties = @{ FLAGS = '6'; VERSION = '131077' }
      (Resolve-MsiConditionExpression -Condition 'FLAGS >< 4' -Property $Properties).State | Should -Be 'True'
      (Resolve-MsiConditionExpression -Condition 'VERSION << 2 AND VERSION >> 5' -Property $Properties).State | Should -Be 'True'
    }

    It 'Should resolve each MSI symbol namespace with its required casing rules' {
      $Result = Resolve-MsiConditionExpression -Condition '(%Path ~= "C:\Tools") AND ($Core=3) AND (?Core=2) AND (&Main=3) AND (!Main=2)' `
        -EnvironmentVariable @{ PATH = 'c:\tools' } -ComponentActionState @{ Core = 3 } -ComponentInstalledState @{ Core = 2 } `
        -FeatureActionState @{ Main = 3 } -FeatureInstalledState @{ Main = 2 }

      $Result.State | Should -Be 'True'
      $Result.ReferencedSymbols.Kind | Should -Be @(
        'EnvironmentVariable', 'ComponentActionState', 'ComponentInstalledState', 'FeatureActionState', 'FeatureInstalledState'
      )
    }

    It 'Should return deterministic invalid results for malformed or over-complex conditions' {
      $UnexpectedPath = Join-Path $PWD '-eq'
      [IO.File]::Delete($UnexpectedPath)

      $Malformed = Resolve-MsiConditionExpression -Condition 'VersionNT64 >= '
      $Malformed.State | Should -Be 'Invalid'
      $Malformed.IsValid | Should -BeFalse
      $Malformed.ErrorPosition | Should -BeGreaterOrEqual 0
      Test-Path -LiteralPath $UnexpectedPath | Should -BeFalse

      (Resolve-MsiConditionExpression -Condition '1 AND 1' -MaximumTokenCount 2).State | Should -Be 'Invalid'
      (Resolve-MsiConditionExpression -Condition '(((1)))' -MaximumDepth 2).State | Should -Be 'Invalid'
    }
  }
}

Describe 'MSI unsupported architecture parser' {
  InModuleScope MSI {
    It 'Should evaluate the supported Boolean architecture-condition subset' {
      Test-MsiArchitectureCondition -Condition 'VersionNT64 AND NOT Arm64' -Architecture x64 | Should -BeTrue
      Test-MsiArchitectureCondition -Condition 'VersionNT64 AND NOT Arm64' -Architecture arm64 | Should -BeFalse
      Test-MsiArchitectureCondition -Condition 'Msix64 = 1' -Architecture x64 | Should -BeTrue
      Test-MsiArchitectureCondition -Condition 'Msix64 <> 1' -Architecture x86 | Should -BeTrue
    }

    It 'Should decline relational MSI conditions without creating redirection files' {
      $UnexpectedPath = Join-Path $PWD '-eq'
      [IO.File]::Delete($UnexpectedPath)

      Test-MsiArchitectureCondition -Condition 'VersionNT64 >= 601' -Architecture x64 | Should -BeTrue
      Test-Path -LiteralPath $UnexpectedPath | Should -BeFalse
    }
  }

  It 'Should detect x64 MSI packages that do not support x86' {
    $Fixture = Get-InstallerFixture -Name 'Talkdesk-3.1.0.msi' -Url 'https://td-infra-prd-us-east-1-s3-atlaselectron.s3.amazonaws.com/talkdesk-3.1.0.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.Template | Should -Be 'x64;1033'
    $Info.PackageArchitecture | Should -Be 'x64'
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Read-UnsupportedArchitecturesFromMsi -Path $Fixture | Should -Be @('x86')
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeFalse
  }

  It 'Should detect arm64 MSI packages that do not support x86 or x64' {
    $Fixture = Get-InstallerFixture -Name 'prisma-arm64.msi' -Url 'https://updates.talon-sec.com/releases/Prisma%20Access%20Browser/win/packaged/arm64/crx_signed_o4_stable_prisma_access_browser_installer_150_33_2_46-150.33.2.46-a92c04e2.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.Template | Should -Be 'Arm64;1033'
    $Info.PackageArchitecture | Should -Be 'arm64'
    $Info.SupportedArchitectures | Should -Be @('arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86', 'x64')
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeTrue
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture arm64 | Should -BeFalse
  }
}
