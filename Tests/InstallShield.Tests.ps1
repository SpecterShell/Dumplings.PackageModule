BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'MSI.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallShield.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallShield'

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

Describe 'InstallShield parser' {
  It 'Should extract MSI metadata from the AntRad installer' {
    $Fixture = Get-InstallerFixture -Name 'antrad_setup.exe' -Url 'https://pathloss.com/antrad_setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'antrad-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info -Name 'AntRad.msi'

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $MsiInfo.ProductName | Should -Be 'AntRad'
      $MsiInfo.ProductVersion | Should -Be '5.01.05'
      $MsiInfo.ProductCode | Should -Be '{9F6A3279-53F2-47C4-8FC8-3149620498EA}'
      $MsiInfo.UpgradeCode | Should -Be '{6767F0A3-5CD9-4B6F-90C4-693DADF557D8}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the Tachograph File Viewer installer' {
    $Fixture = Get-InstallerFixture -Name 'TachoFileViewer_3_40.exe' -Url 'https://www.prosysdev.com/downloads/TachoFileViewer_3_40.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'tachograph-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info -Name 'Tachograph File Viewer.msi'

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $MsiInfo.ProductName | Should -Be 'Tachograph File Viewer'
      $MsiInfo.ProductVersion | Should -Be '3.40'
      $MsiInfo.ProductCode | Should -Be '{AAA4DC80-8FA6-4A8E-AFD2-D82B9CCCA2A8}'
      $MsiInfo.UpgradeCode | Should -Be '{F97E4ADC-C4FE-4253-B342-EC2D8873E27B}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the WiFi Sensor Software installer' {
    $Fixture = Get-InstallerFixture -Name 'WiFi Sensor Software.exe' -Url 'https://s3.amazonaws.com/easylogcloud/WiFi%20Sensor%20Software.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'wifi-sensor-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info -Name 'WiFi Sensor Software.msi'

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $MsiInfo.ProductName | Should -Be 'WiFi Sensor Software'
      $MsiInfo.ProductVersion | Should -Be '1.40.15'
      $MsiInfo.ProductCode | Should -Be '{EF49368B-13B1-4F5B-B453-83C725D31F82}'
      $MsiInfo.UpgradeCode | Should -Be '{60BF28CD-D862-47B9-A3C1-A361DB53CF77}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
