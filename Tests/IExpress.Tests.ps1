BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'General', 'Binary', 'Compression', 'Archive', 'PE', 'Bootstrapper', 'Cabinet', 'IExpress')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\BootstrapperParsers'
  $ProgressPreference = 'SilentlyContinue'

  function Get-BootstrapperFixture {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$Url
    )
    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }
}

Describe 'IExpress parser' {
  It 'Reads script-host commands and cabinet entries from Microsoft Network Monitor' {
    $Installer = Get-BootstrapperFixture -Name 'NM34_x64.exe' -Url 'https://download.microsoft.com/download/7/1/0/7105C7FF-768E-4472-AFD5-F29108D1E383/NM34_x64.exe'
    $Result = Get-IExpressInfo -Path $Installer

    $Result.Format | Should -Be 'IExpress'
    $Result.ExecutedPayloads | Should -Contain 'nmsetup.vbs'
    $Result.NestedFiles | Should -Contain 'netmon.msi'
    $Result.NestedFiles | Should -Contain 'NetworkMonitor_Parsers.msi'
    $Result.Warnings | Should -BeNullOrEmpty
  }
}
