BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'MSI.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\MSI'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }
}

Describe 'MSI Apps & Features parser' {
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
    $Info.AppsAndFeaturesProductCode | Should -Be '{0D35F535-BFC3-482E-96D2-5B8FCE0A4E10}'
    $Info.HasMsqAppsAndFeaturesEntry | Should -BeFalse
    $Info.HidesMsiAppsAndFeaturesEntry | Should -BeFalse
    $Info.MsqAppsAndFeaturesRegistryKey | Should -BeNullOrEmpty
    Test-MsiMsqAppsAndFeaturesEntry -Path $Fixture | Should -BeFalse
    Read-AppsAndFeaturesProductCodeFromMsi -Path $Fixture | Should -Be '{0D35F535-BFC3-482E-96D2-5B8FCE0A4E10}'
  }
}

Describe 'MSI builder and install-location parser' {
  It 'Should read Extension, ProgId, and Verb table associations from draw.io' {
    $Fixture = Get-InstallerFixture -Name 'draw.io-30.2.6.msi' -Url 'https://github.com/jgraph/drawio-desktop/releases/download/v30.2.6/draw.io-30.2.6.msi'
    $Info = Get-MsiAssociationInfo -Path $Fixture

    $Info.Protocols | Should -BeNullOrEmpty
    $Info.FileExtensions | Should -Be @('drawio', 'mermaid', 'mmd', 'vsdx')
    ($Info.FileExtensionAssociations | Where-Object FileExtension -eq 'drawio').DefaultProgId | Should -Be 'draw.io.drawio'
    ($Info.FileExtensionAssociations | Where-Object FileExtension -eq 'drawio').Command | Should -Be 'Open with draw.io'
    Read-FileExtensionsFromMsi -Path $Fixture | Should -Be @('drawio', 'mermaid', 'mmd', 'vsdx')
  }

  It 'Should classify an Advanced Installer MSI with a custom EXE-style ARP entry' {
    $Fixture = Get-InstallerFixture -Name 'Vurbo.ai_1.12.2.2.msi' -Url 'https://ipevo-software.s3.us-east-1.amazonaws.com/Vurbo/Windows/Vurbo.ai_1.12.2.2.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'AdvancedInstaller'
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
    Read-AppsAndFeaturesInstallerTypeFromMsi -Path $Fixture | Should -Be 'msi'
  }

  It 'Should classify an InstallShield-authored MSI and read INSTALLDIR' {
    $Fixture = Get-InstallerFixture -Name 'ProjectViewer_365_PC_26.4.1290.msi' -Url 'https://projectviewercentral.com/download/ProjectViewerPC/365/26/ProjectViewer_365_PC_26.4.1290.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallerBuilder | Should -Be 'InstallShield'
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
    $FigmaInfo.AllUsers | Should -Be '2'
    $FigmaInfo.InstallLocationProperty | Should -Be 'APPLICATIONROOTDIRECTORY'
    $FigmaInfo.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $DrawInfo.InstallerBuilder | Should -Be 'WiX'
    $DrawInfo.InstallLocationProperty | Should -Be 'APPLICATIONFOLDER'
    $DrawInfo.InstallLocationSource | Should -Be 'WIXUI_INSTALLDIR'
  }
}

Describe 'MSI unsupported architecture parser' {
  It 'Should detect x64 MSI packages that do not support x86' {
    $Fixture = Get-InstallerFixture -Name 'Talkdesk-3.1.0.msi' -Url 'https://td-infra-prd-us-east-1-s3-atlaselectron.s3.amazonaws.com/talkdesk-3.1.0.msi'
    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.Template | Should -Be 'x64;1033'
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
    $Info.SupportedArchitectures | Should -Be @('arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86', 'x64')
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture x64 | Should -BeTrue
    Test-MsiUnsupportedArchitecture -Path $Fixture -Architecture arm64 | Should -BeFalse
  }
}
