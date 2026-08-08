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

$FunctionOwners = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$AliasDefinitions = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$VariableValues = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Split implementation modules export selected helpers so sibling modules can call them by
# module-qualified name. Keep those helpers out of PackageModule's supported public surface.
$ParentFunctionAllowLists = @{
  ChromiumUpdater         = @(
    'ConvertFrom-ChromiumUpdaterTagData'
    'Get-MsiChromiumEnterpriseInfoFromStaticTableInfo'
    'Read-ChromiumInstallerTag'
    'Read-MsiChromiumUpdaterTag'
    'Test-ChromiumUpdater'
    'Test-OmahaInstaller'
  )
  ChromiumMiniInstaller   = @('Test-ChromiumMiniInstaller')
  PEArchitecture          = @(
    'Resolve-PortablePEMachineArchitecture'
    'Get-PEFileKind'
    'Get-PortableAnyCpuSupportedArchitecture'
    'Read-ProductVersionFromExe'
    'Read-ProductVersionRawFromExe'
    'Read-FileVersionFromExe'
    'Read-FileVersionRawFromExe'
    'Get-PEArchitectureInfo'
    'Read-ArchitectureFromPE'
    'Test-PEArchitecture'
  )
  InstallShieldContainer  = @(
    'Expand-InstallShieldCabinet'
    'Expand-InstallShieldInstaller'
    'Get-InstallShieldMsiInfo'
    'Read-ProductCodeFromInstallShield'
    'Read-ProductVersionFromInstallShield'
    'Read-UpgradeCodeFromInstallShield'
  )
  InstallShieldAdvancedUI = @(
    'Get-InstallShieldAdvancedUiInfo'
    'Get-InstallShieldAdvancedUiNestedPackageInfo'
    'Get-InstallShieldAdvancedUiPackageEligibility'
    'Get-InstallShieldPrerequisiteInfo'
    'Resolve-InstallShieldSuiteCondition'
  )
}
$ParentPrivateVariables = [System.Collections.Generic.HashSet[string]]::new(
  [string[]]@(
    'ChromiumInstallConstantsSize32'
    'ChromiumInstallConstantsSize64'
    'ChromiumMaximumCertificateBytes'
    'ChromiumMaximumOfflineManifestBytes'
    'ChromiumMaximumResourceBytes'
    'ChromiumUpdaterTagMarker'
    'ChromiumUpdaterWideTagPrefix'
    'ChromiumUpdaterWideTagSuffix'
  ),
  [System.StringComparer]::OrdinalIgnoreCase
)
$CompatibilityVariableNames = @(
  'DumplingsWinGetGitHubRepoDefaultOwner'
  'DumplingsWinGetGitHubRepoDefaultName'
  'DumplingsWinGetGitHubRepoDefaultBranch'
  'DumplingsWinGetGitHubRepoDefaultRootPath'
  'DumplingsWinGetLocalRepoDefaultRootPath'
)

foreach ($RelativePath in $ModulePaths) {
  # Child modules intentionally remain global because their existing functions resolve shared
  # commands through the caller session and Pester targets those child module names directly.
  $ImportedModule = Import-Module (Join-Path $PSScriptRoot $RelativePath) -Force -Global -PassThru -ErrorAction Stop
  $AllowedFunctions = $ParentFunctionAllowLists[$ImportedModule.Name]
  foreach ($Name in $ImportedModule.ExportedFunctions.Keys) {
    if ($null -eq $AllowedFunctions -or $Name -in $AllowedFunctions) { $FunctionOwners[$Name] = $ImportedModule }
  }
  foreach ($Name in $ImportedModule.ExportedAliases.Keys) { $AliasDefinitions[$Name] = $ImportedModule.ExportedAliases[$Name].Definition }
  foreach ($Name in $ImportedModule.ExportedVariables.Keys) {
    if (-not $ParentPrivateVariables.Contains($Name)) { $VariableValues[$Name] = $ImportedModule.ExportedVariables[$Name].Value }
  }
}

# Repository adapters historically exported these configurable names even before Core assigned
# them. Keep the names available for standalone imports without inventing replacement defaults.
foreach ($Name in $CompatibilityVariableNames) {
  $ExistingVariable = Get-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
  $VariableValues[$Name] = $null -ne $ExistingVariable ? $ExistingVariable.Value : $null
}

# Generate parent-owned proxies from the real child command metadata. Module-qualified lookup
# prevents a proxy from recursively resolving itself after PackageModule is imported globally.
foreach ($Entry in $FunctionOwners.GetEnumerator()) {
  $Name = $Entry.Key
  $Owner = $Entry.Value
  $Command = $Owner.ExportedFunctions[$Name]
  $ProxySource = [System.Management.Automation.ProxyCommand]::Create(
    [System.Management.Automation.CommandMetadata]::new($Command)
  )
  $QualifiedName = "$($Owner.Name)\$Name"
  $ProxySource = $ProxySource.Replace("GetCommand('$Name',", "GetCommand('$QualifiedName',")
  # Help resolution must use the same child-module qualification as command invocation. An
  # unqualified forwarding target resolves back to this parent proxy after global import.
  $ProxySource = $ProxySource.Replace(".ForwardHelpTargetName $Name", ".ForwardHelpTargetName $QualifiedName")
  Set-Item -Path "Function:script:$Name" -Value ([scriptblock]::Create($ProxySource))
}

foreach ($Entry in $AliasDefinitions.GetEnumerator()) {
  Set-Alias -Scope Script -Name $Entry.Key -Value $Entry.Value
}

foreach ($Entry in $VariableValues.GetEnumerator()) {
  Set-Variable -Scope Script -Name $Entry.Key -Value $Entry.Value
}

Export-ModuleMember -Function @($FunctionOwners.Keys) -Alias @($AliasDefinitions.Keys) -Variable @($VariableValues.Keys)
