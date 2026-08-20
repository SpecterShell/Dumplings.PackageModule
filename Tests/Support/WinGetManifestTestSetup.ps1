BeforeDiscovery {
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Cabinet.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerDiagnostics.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Data\YamlSchema.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetManifestSchema.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetManifestModel.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetMatching.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetManifestSerialization.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerBridge.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\MSI.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\MSIX.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\Burn.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\NSIS.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\Inno.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\AdvancedInstaller.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\InstallShield.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\ChromiumSetup.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetAnalysis.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetDownload.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetManifestUpdate.psm1') -Force
}
