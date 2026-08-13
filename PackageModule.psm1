# SPDX-License-Identifier: Apache-2.0

# The manifest owns deterministic dependency ordering and the public export surface. This root
# module initializes the few process-wide types required before task models are loaded.

if (-not ([System.Management.Automation.PSTypeName]'Dumplings.Versioning.WinGetVersion').Type) {
  Add-Type -Path (Join-Path $PSScriptRoot 'Assets' 'Source' 'Versioning' 'Versioning.cs')
}

# Preserve the historical short type names used throughout task scripts.
$TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$TypeAccelerators = $TypeAcceleratorsClass::Get
@(
  [Dumplings.Versioning.WinGetVersion]
  [Dumplings.Versioning.ChunkVersion]
) | ForEach-Object -Process {
  if (-not $TypeAccelerators.ContainsKey($_.Name)) { $TypeAcceleratorsClass::Add($_.Name, $_) }
}

$ModulePaths = @(
  'Libraries\Infrastructure\Runtime.psm1'
  'Libraries\Infrastructure\Binary.psm1'
  'Libraries\Infrastructure\FileSystem.psm1'
  'Libraries\Infrastructure\Archive.psm1'
  'Libraries\Infrastructure\PE.psm1'
  'Libraries\Infrastructure\InstallerEvidence.psm1'
  'Libraries\Infrastructure\Cabinet.psm1'
  'Libraries\Infrastructure\InstallerBridge.psm1'
  'Libraries\Data\Text.psm1'
  'Libraries\Data\Format.psm1'
  'Libraries\Data\HTML.psm1'
  'Libraries\Data\Conversion.psm1'
  'Libraries\Data\Object.psm1'
  'Libraries\Data\ProtocolBuffers.psm1'
  'Libraries\Data\YamlSchema.psm1'
  'Libraries\Networking\Web.psm1'
  'Libraries\Networking\GitHub.psm1'
  'Libraries\Networking\SourceIdentity.psm1'
  'Libraries\Infrastructure\PEArchitecture.psm1'
  'Libraries\Infrastructure\PEDependency.psm1'
  'Libraries\Infrastructure\ARP.psm1'
  'Libraries\Installers\Bootstrapper.psm1'
  'Libraries\Installers\DotNetInstaller.psm1'
  'Libraries\Installers\IExpress.psm1'
  'Libraries\Installers\SevenZipSfx.psm1'
  'Libraries\Installers\WinRarSfx.psm1'
  'Libraries\Installers\InstallShieldInstallScript.psm1'
  'Libraries\Installers\InstallShieldMsi.psm1'
  'Libraries\Installers\MSI.psm1'
  'Libraries\Installers\ActualInstaller.psm1'
  'Libraries\Installers\AdvancedInstaller.psm1'
  'Libraries\Installers\Burn.psm1'
  'Libraries\Installers\ChromiumUpdater.psm1'
  'Libraries\Installers\ChromiumMiniInstaller.psm1'
  'Libraries\Installers\ChromiumSetup.psm1'
  'Libraries\Installers\CreateInstall.psm1'
  'Libraries\Installers\DeployMaster.psm1'
  'Libraries\Installers\Inno.psm1'
  'Libraries\Installers\Install4j.psm1'
  'Libraries\Installers\InstallAnywhere.psm1'
  'Libraries\Installers\InstallAware.psm1'
  'Libraries\Installers\InstallBuilder.psm1'
  'Libraries\Installers\InstallForge.psm1'
  'Libraries\Installers\InstallMate.psm1'
  'Libraries\Installers\Kachina.psm1'
  'Libraries\Installers\MicaSetup.psm1'
  'Libraries\Installers\InstallShieldContainer.psm1'
  'Libraries\Installers\InstallShieldAdvancedUI.psm1'
  'Libraries\Installers\InstallShield.psm1'
  'Libraries\Installers\MSIX.psm1'
  'Libraries\Installers\NSIS.psm1'
  'Libraries\Installers\PaquetBuilder.psm1'
  'Libraries\Installers\QSetup.psm1'
  'Libraries\Installers\QtInstallerFramework.psm1'
  'Libraries\Installers\SetupFactory.psm1'
  'Libraries\Installers\Squirrel.psm1'
  'Libraries\Installers\Tauri.psm1'
  'Libraries\Installers\Wise.psm1'
  'Libraries\Installers\ZeroInstall.psm1'
  'Libraries\Infrastructure\InstallerAnalyzer.psm1'
  'Libraries\Browser\WebDriver.psm1'
  'Libraries\Browser\Playwright.psm1'
  'Libraries\Messaging\Messaging.psm1'
  'Libraries\Messaging\Matrix.psm1'
  'Libraries\Messaging\Telegram.psm1'
  'Libraries\Messaging\MessageQueue.psm1'
  'Libraries\Messaging\StatusReport.psm1'
  'Libraries\WinGet\WinGetManifestSchema.psm1'
  'Libraries\WinGet\WinGetManifestModel.psm1'
  'Libraries\WinGet\WinGetAnalysis.psm1'
  'Libraries\WinGet\WinGetMatching.psm1'
  'Libraries\WinGet\WinGetManifestSerialization.psm1'
  'Libraries\WinGet\WinGetDownload.psm1'
  'Libraries\WinGet\WinGetGitHubRepo.psm1'
  'Libraries\WinGet\WinGetLocalRepo.psm1'
  'Libraries\WinGet\WinGetManifestValidation.psm1'
  'Libraries\WinGet\WinGetManifestUpdate.psm1'
  'Libraries\WinGet\WinGetManifestAuthoring.psm1'
  'Libraries\WinGet\WinGetSubmission.psm1'
)

foreach ($RelativePath in $ModulePaths) {
  # Implementation modules retain command ownership and share one caller command table. The root
  # module is only a deterministic loader; creating a second proxy for every command breaks native
  # help/completion metadata and makes each function discoverable under two module names.
  Import-Module (Join-Path $PSScriptRoot $RelativePath) -Force -Global -ErrorAction Stop
}
