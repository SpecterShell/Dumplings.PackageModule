# SPDX-License-Identifier: Apache-2.0
# WinGet-specific projection over provider-neutral installer evidence.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-WinGetInstallerExeFamilyDefault {
  <#
  .SYNOPSIS
    Get suggested manifest defaults for a generic EXE family
  .PARAMETER Family
    The generic EXE family name
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The generic EXE family name')]
    [string]$Family
  )

  switch ($Family) {
    'Advanced Installer' {
      [pscustomobject]@{
        InstallerType       = 'exe # Advanced Installer'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/exenoui /quiet /norestart'; SilentWithProgress = '/exenoui /passive /norestart'; InstallLocation = 'APPDIR="<INSTALLPATH>"'; Log = '/log "<LOGPATH>"' }
        ExpectedReturnCodes = @(
          [ordered]@{ InstallerReturnCode = -1; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 1; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 87; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1601; ReturnResponse = 'contactSupport' },
          [ordered]@{ InstallerReturnCode = 1602; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 1618; ReturnResponse = 'installInProgress' },
          [ordered]@{ InstallerReturnCode = 1623; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1625; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1628; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1633; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1638; ReturnResponse = 'alreadyInstalled' },
          [ordered]@{ InstallerReturnCode = 1639; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1640; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1641; ReturnResponse = 'rebootInitiated' },
          [ordered]@{ InstallerReturnCode = 1643; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1644; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1649; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1650; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1654; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 3010; ReturnResponse = 'rebootRequiredToFinish' }
        )
        Notes               = @('The documented Advanced Installer bootstrapper return codes are included; verify customized launchers and payload-specific codes in a VM.', 'Decide AppsAndFeaturesEntries.InstallerType from the visible ARP entry, not just the embedded MSI.', 'Some packages use EXE ARP and hide MSI ARP with SystemComponent.')
      }
    }
    'InstallShield' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallShield'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S /V/quiet /V/norestart'; SilentWithProgress = '/S /V/passive /V/norestart'; InstallLocation = '/V"INSTALLDIR=""<INSTALLPATH>"""'; Log = '/V"/log ""<LOGPATH>"""' }
        ExpectedReturnCodes = @()
        Notes               = @('Use these switches only for Basic MSI or InstallScript MSI variants.', 'If VM validation proves setup.exe propagates nested MSI exit codes, add the MSI mappings explicitly because the outer type is generic exe.', 'Block InstallScript-only installers that require setup.iss response files.')
      }
    }
    'InstallShield Advanced UI' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallShield Advanced UI'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/passive'; InstallLocation = '/INSTALLDIR="<INSTALLPATH>"' }
        ExpectedReturnCodes = @(
          [ordered]@{ InstallerReturnCode = 0x8004070b; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 0x80040711; ReturnResponse = 'installInProgress' },
          [ordered]@{ InstallerReturnCode = 1601; ReturnResponse = 'contactSupport' },
          [ordered]@{ InstallerReturnCode = 1602; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 1618; ReturnResponse = 'installInProgress' },
          [ordered]@{ InstallerReturnCode = 1623; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1625; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1628; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1633; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1638; ReturnResponse = 'alreadyInstalled' },
          [ordered]@{ InstallerReturnCode = 1639; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1640; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1641; ReturnResponse = 'rebootInitiated' },
          [ordered]@{ InstallerReturnCode = 1643; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1644; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1649; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1650; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1654; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 3010; ReturnResponse = 'rebootRequiredToFinish' }
        )
        Notes               = @('Use only after the package is independently identified as InstallShield Advanced UI.', 'Do not apply these switches to Basic MSI, InstallScript MSI, or InstallScript-only installers.')
      }
    }
    'Squirrel' {
      [pscustomobject]@{
        InstallerType       = 'exe # Squirrel'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '--silent'; SilentWithProgress = '--silent' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('ProductCode is usually the embedded .nuspec id.', 'VM-check HKCU ARP, install path, and upgrade behavior.', 'Velopack descendants may need different uninstall behavior.')
      }
    }
    'Zero Install' {
      [pscustomobject]@{
        InstallerType       = 'exe # Zero Install'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '--verysilent'; SilentWithProgress = '--silent'; InstallLocation = '--store-path="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @(
          'Parse ZeroInstall.BootstrapConfig.ini once with Get-ZeroInstallInfo; target version, publisher, architecture, and capabilities come from caller-supplied feed XML.',
          'The default ARP entry is per-user and --machine selects machine integration only when integrate_args is configured.',
          'Zero Install integration does not write DisplayVersion; validate target-application behavior in a VM.'
        )
      }
    }
    'MicaSetup' {
      [pscustomobject]@{
        InstallerType       = 'exe # MicaSetup'
        InstallModes        = @('interactive')
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @(
          'Use Get-MicaSetupInfo once for compiled Pack/Option, ARP, scope, resource, payload architecture, and dependency evidence.',
          'Upstream /q and /a handling is unfinished; add silent switches only when the exact fork proves and passes unattended VM validation.',
          'Treat Kachina Installer as a separate family even when an older package manifest was labeled MicaSetup.'
        )
      }
    }
    'Kachina' {
      [pscustomobject]@{
        InstallerType       = 'exe # Kachina'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '-S'; SilentWithProgress = '-I'; InstallLocation = '-D "<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        ElevationRequirement = 'elevatesSelf'
        Notes               = @(
          'Use Get-KachinaInfo once for compiled configuration, indexed payload, ARP, scope, architecture, runtime, and patch evidence.',
          'The default Program Files route is machine scope. Non-force UAC strategies can use user scope only when -D selects an eligible user-writable path.',
          'Configured or appended runtime packages are evidence; do not copy them into manifest Dependencies without validating the application requirements.'
        )
      }
    }
    'Velopack' {
      [pscustomobject]@{
        InstallerType       = 'exe # Velopack'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '--silent'; SilentWithProgress = '--silent'; InstallLocation = '--installto "<INSTALLPATH>"'; Log = '--log "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('ProductCode is usually the embedded .nuspec id.', 'VM-check HKCU ARP, install path, and upgrade behavior.')
      }
    }
    'Setup Factory' {
      [pscustomobject]@{
        InstallerType       = 'exe # Setup Factory'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
        ExpectedReturnCodes = @()
        Notes               = @('Use Get-SetupFactoryInfo for structured session variables, built-in uninstall settings, literal registry actions, ProductCode, publisher, and scope.', 'Verify case-sensitive switches and any required no-restart option in a VM.')
      }
    }
    'InstallAnywhere' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallAnywhere'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '-i silent'; SilentWithProgress = '-i silent'; InstallLocation = '-DUSER_INSTALL_DIR="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Stop if the package requires an installer.properties response file that cannot be expressed statically.')
      }
    }
    'InstallAware' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallAware'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/s'; SilentWithProgress = '/s'; InstallLocation = 'TARGETDIR="<INSTALLPATH>"'; Log = '/l="<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Confirm exact switches; some InstallAware packages are MSI-backed and may forward MSI properties.')
      }
    }
    'Actual Installer' {
      [pscustomobject]@{
        InstallerType       = 'exe # Actual Installer'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S /L'; SilentWithProgress = '/S /L'; Interactive = '/L'; InstallLocation = '/D "<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        ScopeSwitches       = [pscustomobject]@{ User = '/CU'; Machine = '/RUNAS /ALL' }
        Notes               = @('Actual Installer can use /CU for current-user scope and /RUNAS /ALL for machine scope.', 'Verify package-specific ARP data and whether the setup permits both scopes.')
      }
    }
    'DeployMaster' {
      [pscustomobject]@{
        InstallerType       = 'exe # DeployMaster'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/silent'; InstallLocation = '/appfolder "<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Verify accepted switch spelling and visible ARP entry in a VM.')
      }
    }
    '7z SFX' {
      [pscustomobject]@{
        InstallerType       = 'exe # 7z SFX'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '-y'; SilentWithProgress = '-y' }
        ExpectedReturnCodes = @()
        Notes               = @('7z SFX is a wrapper; inspect the SFX config/comment and analyze the configured nested payload before choosing final switches or ARP metadata.', 'Use MSI/WiX AppsAndFeaturesEntries only when the nested installer writes a Windows Installer ARP entry.')
      }
    }
    'WinRAR GUI SFX' {
      [pscustomobject]@{
        InstallerType       = 'exe # WinRAR GUI SFX'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
        ExpectedReturnCodes = @()
        Notes               = @('WinRAR GUI SFX is a wrapper; inspect the SFX comment/config and analyze the configured nested payload before choosing final switches or ARP metadata.', 'Use MSI/WiX AppsAndFeaturesEntries only when the nested installer writes a Windows Installer ARP entry.')
      }
    }
    'InstallMate' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallMate'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/q2 /b0'; SilentWithProgress = '/q1 /b0'; InstallLocation = '"INSTALLDIR=<INSTALLPATH>"'; Log = '/log:"<LOGPATH>"' }
        ExpectedReturnCodes = @(
          [ordered]@{ InstallerReturnCode = 5; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 9; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 11; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 12; ReturnResponse = 'rebootRequiredToFinish' },
          [ordered]@{ InstallerReturnCode = 13; ReturnResponse = 'packageInUse' },
          [ordered]@{ InstallerReturnCode = 14; ReturnResponse = 'alreadyInstalled' },
          [ordered]@{ InstallerReturnCode = 16; ReturnResponse = 'diskFull' },
          [ordered]@{ InstallerReturnCode = 20; ReturnResponse = 'installInProgress' }
        )
        Notes               = @('Verify accepted switch spelling; InstallMate packages may customize command line handling.')
      }
    }
    'QSetup' {
      [pscustomobject]@{
        InstallerType       = 'exe # QSetup'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/hide'; SilentWithProgress = '/silent'; InstallLocation = '/InstallDir="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Verify switches and ARP data in a VM.')
      }
    }
    'install4j' {
      [pscustomobject]@{
        InstallerType       = 'exe # install4j'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '-q -Dinstall4j.suppressUnattendedReboot=true'; SilentWithProgress = '-q -splash "" -Dinstall4j.suppressUnattendedReboot=true'; InstallLocation = '-dir "<INSTALLPATH>"'; Log = '-Dinstall4j.log="<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Use Get-Install4jInfo for static ProductCode, DisplayVersion, publisher, ARP-action, and scope evidence.', 'Use package docs or VM output to confirm unattended mode and directory switch.', 'Scope may depend on UAC availability; do not set Scope without parser evidence or VM validation.')
      }
    }
    'dotNetInstaller' {
      [pscustomobject]@{
        InstallerType       = 'exe # dotNetInstaller'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/q /nosplash /ComponentArgs "*":"/quiet /norestart"'; SilentWithProgress = '/qb /ComponentArgs "*":"/passive /norestart"'; Log = '/Log /LogFile "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Confirm bundled prerequisite handling and final ARP entry in a VM.')
      }
    }
    'IExpress' {
      [pscustomobject]@{
        InstallerType       = 'exe # IExpress'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/Q'; SilentWithProgress = '/Q'; Log = '/L:"<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('IExpress is a self-extracting wrapper; inspect the package command and nested payload before trusting switches or ARP metadata.', 'The visible Apps & Features entry normally comes from the nested installer or launched command.')
      }
    }
    'Wise' {
      [pscustomobject]@{
        InstallerType       = 'exe # Wise MSI'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/quiet /norestart'; SilentWithProgress = '/passive /norestart'; InstallLocation = 'INSTALLDIR="<INSTALLPATH>"'; Log = '/log "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('These defaults apply to the Wise-for-Windows-Installer MSI wrapper parsed by Get-WiseInfo, not every Wise generation.', 'If VM validation proves the Wise wrapper propagates nested MSI exit codes, add the MSI mappings explicitly because the outer type is generic exe.', 'Use the nested MSI for ProductCode, UpgradeCode, install-location property, associations, scope evidence, and AppsAndFeaturesEntries.InstallerType.')
      }
    }
    'Chromium Setup' {
      [pscustomobject]@{
        InstallerType       = 'exe # Chromium Setup'
        InstallModes        = @()
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('First distinguish ChromiumMiniInstaller, ChromiumUpdater, and Omaha with Get-ChromiumSetupInfo.', 'Do not copy switches across Chromium vendor forks; 360, Brave, Chrome, Vivaldi, Maxthon, and other packages customize setup behavior.', 'An updater appguid is update-protocol identity and must not be used as ProductCode.')
      }
    }
    'InstallBuilder' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallBuilder'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '--mode unattended'; SilentWithProgress = '--mode unattended --unattendedmodeui minimal'; InstallLocation = '--prefix "<INSTALLPATH>"'; Log = '--debugtrace "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('InstallBuilder --help commonly opens a transient GUI help window; prefer static strings, vendor docs, or VM validation.', 'Verify whether the package supports user or machine scope before setting Scope.')
      }
    }
    'Paquet Builder' {
      [pscustomobject]@{
        InstallerType       = 'exe # Paquet Builder'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/s'; SilentWithProgress = '/s' }
        ExpectedReturnCodes = @()
        Notes               = @('Paquet Builder 2026.1 and later recognize /s and /silent natively when the project keeps that option enabled.', 'Older or customized packages may require project-defined command-line parsing; verify the exact package.')
      }
    }
    'CreateInstall' {
      [pscustomobject]@{
        InstallerType       = 'exe # CreateInstall'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '-silent'; SilentWithProgress = '-silent' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('Accepted Novostrim.CreateInstall manifests use -silent, but custom CreateInstall projects may differ.', 'Verify package-specific ProductCode and visible ARP data in a VM.')
      }
    }
    'InstallForge' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallForge'
        InstallModes        = @('interactive')
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('InstallForge does not support WinGet-compatible silent installation. Do not submit unless a separate verified silent-capable build or wrapper exists.')
      }
    }
    'Qt Installer Framework' {
      [pscustomobject]@{
        InstallerType       = 'exe # Qt Installer Framework'
        InstallModes        = @('interactive', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = 'install --root "<INSTALLPATH>" --accept-licenses --default-answer --confirm-command'; SilentWithProgress = 'install --root "<INSTALLPATH>" --accept-licenses --default-answer --confirm-command' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'uninstallPrevious'
        Notes               = @('Use these switches only when Get-QtInstallerFrameworkInfo reports InterfaceVariant=CLI and SupportsSilentInstallation=true.', 'Keep --root in Silent and SilentWithProgress only when RequiresExplicitInstallLocation=true; otherwise expose it as InstallLocation.', 'Qt IFW writes HKLM ARP only when the AllUsers variable is true; otherwise it writes HKCU ARP.', 'Use AllUsers=true or AllUsers=false as a custom switch only when parser evidence confirms the CLI path.')
      }
    }
    default {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @()
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('Unknown EXE family; do not submit without documented or VM-verified silent switches.')
      }
    }
  }
}

function Add-WinGetInstallerProjection {
  <#
  .SYNOPSIS
    Add WinGet manifest suggestions to generic installer-family evidence.
  .PARAMETER InputObject
    Generic analyzer result whose family records should receive WinGet defaults.
  #>
  param ([Parameter(Mandatory)][object]$InputObject)

  # Get-InstallerAnalysis receives the WinGet projection provider before parsing so family-specific
  # evidence can refine the defaults in place. This function remains as the stable projection seam.
  return $InputObject
}

function Get-WinGetInstallerAnalysis {
  <#
  .SYNOPSIS
    Analyze an installer and add WinGet-specific manifest recommendations.
  .PARAMETER Path
    Installer path to analyze without execution.
  .PARAMETER ScanBytes
    Bounded byte budget for family heuristics.
  .PARAMETER ExtractEmbeddedMsi
    Extract embedded MSI metadata when a supported wrapper exposes it.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$Path,
    [ValidateRange(4096, 268435456)][int64]$ScanBytes = 16777216,
    [switch]$ExtractEmbeddedMsi
  )
  process {
    $Result = Get-InstallerAnalysis -Path $Path -ScanBytes $ScanBytes -ExtractEmbeddedMsi:$ExtractEmbeddedMsi -FamilyProjectionProvider {
      param([string]$Family)
      Get-WinGetInstallerExeFamilyDefault -Family $Family
    }
    Add-WinGetInstallerProjection -InputObject $Result
  }
}

Export-ModuleMember -Function Get-WinGetInstallerAnalysis
