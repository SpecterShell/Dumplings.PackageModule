# SPDX-License-Identifier: Apache-2.0
# WinGet-specific projection over provider-neutral installer evidence.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-WinGetInstallerFamilyTemplate {
  <#
  .SYNOPSIS
    Get WinGet authoring defaults for an installer family.
  .PARAMETER Family
    The detected installer family or known WinGet installer category.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer family or known WinGet installer category')]
    [string]$Family
  )

  switch ($Family) {
    'MSI' { [pscustomobject]@{ InstallerType = 'msi'; Notes = @('Use the parser-reported msi or wix type; do not infer the builder from the file extension.') } }
    'MSIX/AppX' { [pscustomobject]@{ InstallerType = 'msix'; Notes = @('Use the parser-reported appx, msix, or bundle type and retain only source-backed package metadata.') } }
    { $_ -cin @('ZIP', 'ZIP/archive', 'Archive') } { [pscustomobject]@{ InstallerType = 'zip'; Notes = @('Select one nested installer before adding NestedInstallerType and NestedInstallerFiles.') } }
    'Portable' { [pscustomobject]@{ InstallerType = 'portable'; Notes = @('Use a concrete architecture for every package containing a binary file.') } }
    'Font' { [pscustomobject]@{ InstallerType = 'font'; Notes = @() } }
    'Burn' { [pscustomobject]@{ InstallerType = 'burn'; Notes = @('WinGet supplies the known Burn defaults; author only artifact-specific overrides.') } }
    'Inno Setup' { [pscustomobject]@{ InstallerType = 'inno'; Notes = @('WinGet supplies the known Inno defaults; author only artifact-specific overrides.') } }
    'NSIS/Nullsoft' { [pscustomobject]@{ InstallerType = 'nullsoft'; Notes = @('WinGet supplies the known NSIS defaults; author only artifact-specific overrides.') } }
    'MSP' { [pscustomobject]@{ Notes = @('MSP files patch an existing Windows Installer product and are not standalone WinGet installer entries.') } }
    'Squirrel/Velopack' { [pscustomobject]@{ InstallerType = 'exe'; Notes = @('Package metadata was found without a decisive Squirrel or Velopack launcher structure; validate the outer command line before authoring switches.') } }
    'Advanced Installer' {
      [pscustomobject]@{
        InstallerType       = 'exe'
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
        InstallerType = 'exe'
        Notes         = @('Classify the package as Basic MSI, InstallScript MSI, InstallScript-only, or Advanced UI before authoring family-specific switches.')
      }
    }
    'InstallShield MSI Wrapper' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S /V/quiet /V/norestart'; SilentWithProgress = '/S /V/passive /V/norestart'; InstallLocation = '/V"INSTALLDIR=\"<INSTALLPATH>\""'; Log = '/V"/log \"<LOGPATH>\""' }
        ExpectedReturnCodes = @()
        Notes               = @('Use these switches only for Basic MSI or InstallScript MSI variants.', 'If VM validation proves setup.exe propagates nested MSI exit codes, add the MSI mappings explicitly because the outer type is generic exe.', 'Block InstallScript-only installers that require setup.iss response files.')
      }
    }
    'InstallShield Advanced UI' {
      [pscustomobject]@{
        InstallerType       = 'exe'
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
        InstallerType       = 'exe'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '--silent'; SilentWithProgress = '--silent' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('Use only when the PE resource DATA/#131 route identifies Squirrel.Windows.', 'ProductCode is usually the embedded .nuspec id.', 'VM-check HKCU ARP, install path, and upgrade behavior.')
      }
    }
    'Zero Install' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '--verysilent'; SilentWithProgress = '--silent'; InstallLocation = '--store-path="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @(
          'Parse the source-backed legacy CLR identity or generation-specific EmbeddedConfig.txt, config.ini, or BootstrapConfig.ini once with Get-ZeroInstallInfo; target version, publisher, architecture, and capabilities come from caller-supplied feed XML.',
          'The default ARP entry is per-user and --machine selects machine integration only when integrate_args is configured.',
          'Zero Install integration does not write DisplayVersion; validate target-application behavior in a VM.'
        )
      }
    }
    'TigerSetup' {
      return [pscustomobject]@{
        Family            = 'TigerSetup'
        InstallerType     = 'exe'
        InstallerSwitches = [ordered]@{ Silent = 'install --quiet'; SilentWithProgress = 'install --quiet'; Log = '--log "<LOGPATH>"' }
        InstallModes      = @('interactive', 'silent', 'silentWithProgress')
        Notes             = @('Use Get-TigerSetupInfo for compiled scope, ARP and option evidence; choose an explicit --scope route for dual-scope media and validate it in a VM.')
      }
    }
    'MicaSetup' {
      [pscustomobject]@{
        InstallerType       = 'exe'
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
        InstallerType        = 'exe'
        InstallModes         = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches    = [ordered]@{ Silent = '-S'; SilentWithProgress = '-I'; InstallLocation = '-D "<INSTALLPATH>"' }
        ExpectedReturnCodes  = @()
        ElevationRequirement = 'elevatesSelf'
        Notes                = @(
          'Use Get-KachinaInfo once for compiled configuration, indexed payload, ARP, scope, architecture, runtime, and patch evidence.',
          'The default Program Files route is machine scope. Non-force UAC strategies can use user scope only when -D selects an eligible user-writable path.',
          'Configured or appended runtime packages are evidence; do not copy them into manifest Dependencies without validating the application requirements.'
        )
      }
    }
    'Astrum InstallWizard' {
      [pscustomobject]@{
        InstallerType = 'exe'
        Notes         = @(
          'Use Get-AstrumInstallWizardInfo once for compiled registry, ARP, operation, payload, architecture, and dependency evidence.',
          'Verified 2.x media uses /silent and reports exit code 1 as success. Exact parser evidence adds /AcceptLicense when required; an Early2 User Information dialog remains interactive-only, while VM-validated Modern2 runtimes skip that dialog during silent installation.',
          'Astrum 1.x requires a delimited /SILENT token in the exact runtime or artifact-specific VM evidence because silent support was introduced during that generation.',
          'Spanned media and tiny wrappers require a structurally verified route before extraction.'
        )
      }
    }
    'AKInstaller' {
      [pscustomobject]@{
        InstallerType = 'exe'
        Notes         = @(
          'Use Get-AKInstallerInfo once for the compiled native project table or AKInstallerMSI configuration and nested MSI evidence.',
          'Use explicit native registry rows or nested MSI metadata for ProductCode and AppsAndFeaturesEntries; PE version strings are not ARP evidence.',
          'Only exact parser evidence should add switches because native AKInstaller and AKInstallerMSI use different command lines.'
        )
      }
    }
    'Dell Update Package' {
      [pscustomobject]@{
        InstallerType = 'exe'
        Notes         = @('Use Mup.xml to select the vendor executable; nested metadata owns ARP.', 'Prefer the selected nested family defaults through /passthrough without merging embedded MUP arguments. Inspect the EmbeddedMup alternative if VM validation fails; otherwise keep the wrapper route for unresolved nested families.', 'Dell applicability can reject unsupported hardware before the nested installer runs.')
      }
    }
    'Velopack' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '--silent'; SilentWithProgress = '--silent'; InstallLocation = '--installto "<INSTALLPATH>"'; Log = '--log "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('Use only when Get-SquirrelInfo validates Clowd DATA/#205 or a signed Velopack-family bundle; apply command-line fields from its launcher capabilities.', 'ProductCode is usually the embedded .nuspec id.', 'VM-check HKCU ARP, install path, and upgrade behavior.')
      }
    }
    'Setup Factory' {
      [pscustomobject]@{
        InstallerType = 'exe'
        Notes         = @('Use Get-SetupFactoryInfo for structured session variables, built-in uninstall settings, literal registry actions, ProductCode, publisher, scope, and silent-mode evidence.', 'Setup Factory 3.1, 4, and 5 are interactive-only, version 6 implements /S, and versions 7 through 10 use the compiled project gate. Add /S only when the exact artifact reports SupportsSilentInstallation as true.')
      }
    }
    'InstallAnywhere' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '-i silent'; SilentWithProgress = '-i silent'; InstallLocation = '-DUSER_INSTALL_DIR="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Stop if the package requires an installer.properties response file that cannot be expressed statically.')
      }
    }
    'InstallAware' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/s'; SilentWithProgress = '/s'; InstallLocation = 'TARGETDIR="<INSTALLPATH>"'; Log = '/l="<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Confirm exact switches; some InstallAware packages are MSI-backed and may forward MSI properties.')
      }
    }
    'Actual Installer' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/S'; InstallLocation = '/D "<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        ScopeSwitches       = [pscustomobject]@{ User = '/CU'; Machine = '/RUNAS /ALL' }
        Notes               = @('Actual Installer can use /CU for current-user scope and /RUNAS /ALL for machine scope when the compiled InstallLevel permits both.', 'The /L switch writes a fixed AISETUPLOG.TXT file and does not define a separate progress mode.', 'Verify package-specific ARP data and whether the setup permits both scopes.')
      }
    }
    'DeployMaster' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/silent'; InstallLocation = '/appfolder "<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('DeployMaster documents /silent as fully hidden; it does not provide a distinct silent-with-progress mode.', 'Validate nested prerequisite behavior and the visible ARP entry in a VM.')
      }
    }
    '7z SFX' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '-y'; SilentWithProgress = '-y' }
        ExpectedReturnCodes = @()
        Notes               = @('7z SFX is a wrapper; inspect the SFX config/comment and analyze the configured nested payload before choosing final switches or ARP metadata.', 'Use MSI/WiX AppsAndFeaturesEntries only when the nested installer writes a Windows Installer ARP entry.')
      }
    }
    'WinRAR GUI SFX' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
        ExpectedReturnCodes = @()
        Notes               = @('WinRAR GUI SFX is a wrapper; inspect the SFX comment/config and analyze the configured nested payload before choosing final switches or ARP metadata.', 'Use MSI/WiX AppsAndFeaturesEntries only when the nested installer writes a Windows Installer ARP entry.')
      }
    }
    'InstallMate' {
      [pscustomobject]@{
        InstallerType       = 'exe'
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
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/hide'; SilentWithProgress = '/silent'; InstallLocation = '/InstallDir="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Verify switches and ARP data in a VM.')
      }
    }
    'install4j' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '-q -Dinstall4j.suppressUnattendedReboot=true'; SilentWithProgress = '-q -splash "" -Dinstall4j.suppressUnattendedReboot=true'; InstallLocation = '-dir "<INSTALLPATH>"'; Log = '-Dinstall4j.log="<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Use Get-Install4jInfo for static ProductCode, DisplayVersion, publisher, ARP-action, and scope evidence.', 'Use package docs or VM output to confirm unattended mode and directory switch.', 'Scope may depend on UAC availability; do not set Scope without parser evidence or VM validation.')
      }
    }
    'dotNetInstaller' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/q' }
        ExpectedReturnCodes = @()
        Notes               = @('Use Get-DotNetInstallerInfo to add /qb, /nosplash, /noreboot, and logging only when the compiled runtime exposes those capabilities.', 'Do not add blanket /ComponentArgs values; dotNetInstaller already selects each component command for the requested UI mode.', 'Confirm conditional prerequisites and the final ARP owner in a VM when static filters remain ambiguous.')
      }
    }
    'IExpress' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/Q'; SilentWithProgress = '/Q'; Log = '/L:"<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('IExpress is a self-extracting wrapper; inspect the package command and nested payload before trusting switches or ARP metadata.', 'The visible Apps & Features entry normally comes from the nested installer or launched command.')
      }
    }
    'Wise' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @()
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('Wise behavior is route-specific. Use Get-WiseInfo to distinguish direct Wise MSI wrappers, classic WiseScript installers, and WiseScript prerequisite wrappers.', 'Use a validated nested MSI for ProductCode, UpgradeCode, install-location property, associations, scope evidence, and AppsAndFeaturesEntries.InstallerType.', 'Do not add /S or MSI quiet switches to a WiseScript prerequisite wrapper unless VM validation proves that the nested installer also runs unattended.')
      }
    }
    'Chromium Setup' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @()
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('First distinguish ChromiumMiniInstaller, ChromiumUpdater, and Omaha with Get-ChromiumSetupInfo.', 'Do not copy switches across Chromium vendor forks; 360, Brave, Chrome, Vivaldi, Maxthon, and other packages customize setup behavior.', 'An updater appguid is update-protocol identity and must not be used as ProductCode.')
      }
    }
    'InstallBuilder' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        ExpectedReturnCodes = @()
        Notes               = @('Parse the compiled project before suggesting modes or switches: projects can exclude unattended mode and can rename the install-directory option.', 'InstallBuilder --help commonly opens a transient GUI help window; prefer static project evidence, vendor docs, or VM validation.', 'Verify whether the package supports user or machine scope before setting Scope.')
      }
    }
    'Paquet Builder' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        ExpectedReturnCodes = @()
        Notes               = @('Use exact parser evidence before suggesting Paquet Builder switches or modes; historical resource-runtime generations do not share the current compiled command-line route.')
      }
    }
    'CreateInstall' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        ExpectedReturnCodes = @()
        Notes               = @('CreateInstall scope, silent modes, and silent switches are compiled project settings. Use exact parser evidence instead of family defaults.', 'Verify package-specific ProductCode and visible ARP data in a VM when deterministic registry writes do not prove one visible uninstall key.')
      }
    }
    'InstallForge' {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @('interactive')
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('InstallForge does not support WinGet-compatible silent installation. Do not submit unless a separate verified silent-capable build or wrapper exists.')
      }
    }
    'Qt Installer Framework' {
      [pscustomobject]@{
        InstallerType = 'exe'
        Notes         = @('Use CLI switches only when Get-QtInstallerFrameworkInfo reports InterfaceVariant=CLI and SupportsSilentInstallation=true.', 'Qt IFW writes HKLM ARP only when the AllUsers variable is true; otherwise it writes HKCU ARP.')
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

function Get-WinGetSuggestionPropertyValue {
  <#
  .SYNOPSIS
    Read the first present property from installer evidence.
  .PARAMETER InputObject
    Evidence object or dictionary.
  .PARAMETER Name
    Property names in priority order.
  #>
  param (
    [AllowNull()]$InputObject,
    [Parameter(Mandatory)][string[]]$Name
  )

  if ($null -eq $InputObject) { return $null }
  foreach ($CandidateName in $Name) {
    if ($InputObject -is [System.Collections.IDictionary]) {
      if ($InputObject.Contains($CandidateName)) { return , $InputObject[$CandidateName] }
    } else {
      $Property = $InputObject.PSObject.Properties[$CandidateName]
      if ($Property) { return , $Property.Value }
    }
  }
  return $null
}

function Test-WinGetSuggestionValue {
  <#
  .SYNOPSIS
    Test whether a proposed manifest value contains authored data.
  .PARAMETER Value
    Candidate manifest value.
  #>
  [OutputType([bool])]
  param ([AllowNull()]$Value)

  if ($null -eq $Value) { return $false }
  if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
  if ($Value -is [System.Collections.IDictionary]) { return $Value.Count -gt 0 }
  if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -gt 0 }
  return $true
}

function ConvertTo-WinGetSuggestionValue {
  <#
  .SYNOPSIS
    Normalize a proposed manifest value and remove empty nested values.
  .PARAMETER Value
    Scalar, dictionary, object, or sequence to normalize.
  #>
  param ([AllowNull()]$Value)

  if (-not (Test-WinGetSuggestionValue -Value $Value)) { return $null }
  if ($Value -is [System.Collections.IDictionary]) {
    $Result = [ordered]@{}
    foreach ($Key in $Value.Keys) {
      $NestedValue = ConvertTo-WinGetSuggestionValue -Value $Value[$Key]
      if (Test-WinGetSuggestionValue -Value $NestedValue) { $Result[$Key] = $NestedValue }
    }
    return $Result
  }
  # The [pscustomobject] accelerator resolves to PSObject and therefore matches every wrapped
  # PowerShell value with -is. Compare against the concrete type so only property bags become
  # schema-ready dictionaries; arrays and scalars must retain their original shapes.
  if ($Value.GetType() -eq [System.Management.Automation.PSCustomObject]) {
    $Result = [ordered]@{}
    foreach ($Property in $Value.PSObject.Properties) {
      $NestedValue = ConvertTo-WinGetSuggestionValue -Value $Property.Value
      if (Test-WinGetSuggestionValue -Value $NestedValue) { $Result[$Property.Name] = $NestedValue }
    }
    return $Result
  }
  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    $Result = [System.Collections.Generic.List[object]]::new()
    foreach ($Item in $Value) {
      $NestedValue = ConvertTo-WinGetSuggestionValue -Value $Item
      if (Test-WinGetSuggestionValue -Value $NestedValue) { $Result.Add($NestedValue) }
    }
    return , $Result.ToArray()
  }
  return $Value
}

function ConvertTo-WinGetSuggestedInstallerType {
  <#
  .SYNOPSIS
    Normalize an analyzer installer type to a WinGet schema value.
  .PARAMETER InstallerType
    Analyzer or parser installer type.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$InstallerType)

  if ([string]::IsNullOrWhiteSpace($InstallerType)) { return $null }
  $Normalized = ($InstallerType -split '\s+#', 2)[0].Trim().ToLowerInvariant()
  if ($Normalized -ceq 'msixbundle') { $Normalized = 'msix' }
  if ($Normalized -ceq 'appxbundle') { $Normalized = 'appx' }
  $Schema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion '1.12.0'
  $AllowedTypes = @($Schema['definitions']['InstallerType']['enum'])
  if ($Normalized -cin $AllowedTypes) { return $Normalized }
  return $null
}

function ConvertTo-WinGetSuggestedManifestFieldSet {
  <#
  .SYNOPSIS
    Keep only nonempty, installer-level fields accepted by the WinGet schema.
  .PARAMETER InputObject
    Partial manifest suggestion to normalize.
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param ([AllowNull()]$InputObject)

  $Result = [ordered]@{}
  if ($null -eq $InputObject) { return $Result }
  $Schema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion '1.12.0'
  $InstallerSchema = $Schema['definitions']['Installer']
  $AllowedFields = Get-WinGetInstallerPropertyCatalog -ManifestVersion '1.12.0'
  foreach ($Field in $AllowedFields) {
    $Value = Get-WinGetSuggestionPropertyValue -InputObject $InputObject -Name $Field
    if ($Field -ceq 'InstallerType') {
      $Value = ConvertTo-WinGetSuggestedInstallerType -InstallerType ([string]$Value)
    } elseif ($Field -ceq 'AppsAndFeaturesEntries' -and $Value) {
      # Parser evidence can carry richer ARP objects than the manifest schema.
      # Project only authored ARP fields instead of leaking internal MSI flags,
      # builder evidence, or compatibility aliases into a suggestion.
      $ProjectedEntries = [Collections.Generic.List[object]]::new()
      $EntrySchema = $InstallerSchema['properties']['AppsAndFeaturesEntries']['items']
      foreach ($Entry in @($Value)) {
        $ProjectedEntry = [ordered]@{}
        foreach ($EntryField in $EntrySchema['properties'].Keys) {
          $EntryValue = ConvertTo-WinGetSuggestionValue -Value (Get-WinGetSuggestionPropertyValue -InputObject $Entry -Name $EntryField)
          if (Test-WinGetSuggestionValue -Value $EntryValue) { $ProjectedEntry[$EntryField] = $EntryValue }
        }
        if ($ProjectedEntry.Count -gt 0) { $ProjectedEntries.Add($ProjectedEntry) }
      }
      $Value = @($ProjectedEntries)
    }
    $Value = ConvertTo-WinGetSuggestionValue -Value $Value
    if (-not (Test-WinGetSuggestionValue -Value $Value)) { continue }
    $Validation = Get-YamlSchemaValidationResult -InputObject $Value -Schema $InstallerSchema['properties'][$Field] -RootSchema $Schema
    if (-not $Validation.IsValid) { continue }
    $Result[$Field] = $Value
  }

  # WinGet defaults to SilentWithProgress and warns when either unattended
  # switch is absent for an effective EXE. A fully silent route is a safe
  # fallback for that slot even when the installer has no progress UI.
  $EffectiveInstallerType = if ($Result['InstallerType'] -ceq 'zip') { $Result['NestedInstallerType'] } else { $Result['InstallerType'] }
  $Switches = $Result['InstallerSwitches']
  if ($EffectiveInstallerType -ceq 'exe' -and $Switches -is [System.Collections.IDictionary] -and $Switches.Contains('Silent') -and -not $Switches.Contains('SilentWithProgress')) {
    $Switches['SilentWithProgress'] = $Switches['Silent']
  }
  return $Result
}

function Merge-WinGetSuggestedManifestFieldSet {
  <#
  .SYNOPSIS
    Merge a schema-valid partial manifest patch over common suggestion fields.
  .PARAMETER Base
    Common manifest fields.
  .PARAMETER Override
    Variant or parser-specific fields.
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Base,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Override
  )

  ConvertTo-WinGetSuggestedManifestFieldSet -InputObject (Merge-WinGetManifestDictionary -Base $Base -Override $Override)
}

function ConvertTo-WinGetSuggestedManifestVariant {
  <#
  .SYNOPSIS
    Create one complete scope, subtype, or command-route manifest suggestion.
  .PARAMETER Name
    Stable human-readable variant name.
  .PARAMETER ManifestFields
    Complete schema-valid partial manifest fields for the variant.
  .PARAMETER Evidence
    Parser or workflow evidence supporting the variant.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][System.Collections.IDictionary]$ManifestFields,
    [AllowNull()]$Evidence
  )

  [pscustomobject][ordered]@{
    Name           = $Name
    ManifestFields = [pscustomobject](ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $ManifestFields)
    Evidence       = $Evidence
  }
}

function Get-WinGetInstallerFamilySuggestion {
  <#
  .SYNOPSIS
    Get schema-valid WinGet suggestions and separate authoring guidance for a family.
  .PARAMETER Family
    Confirmed or candidate installer family.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Family)

  $Template = Get-WinGetInstallerFamilyTemplate -Family $Family
  $ManifestFields = ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Template
  $Variants = [System.Collections.Generic.List[object]]::new()
  $ScopeSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Template -Name ScopeSwitches
  if ($ScopeSwitches) {
    foreach ($Scope in @('user', 'machine')) {
      $CustomSwitch = Get-WinGetSuggestionPropertyValue -InputObject $ScopeSwitches -Name ($Scope -eq 'user' ? 'User' : 'Machine')
      if ([string]::IsNullOrWhiteSpace([string]$CustomSwitch)) { continue }
      $VariantFields = [ordered]@{ Scope = $Scope }
      $VariantSwitches = [ordered]@{}
      $CommonSwitches = Get-WinGetSuggestionPropertyValue -InputObject $ManifestFields -Name InstallerSwitches
      if ($CommonSwitches -is [System.Collections.IDictionary]) {
        foreach ($Key in $CommonSwitches.Keys) { $VariantSwitches[$Key] = Copy-Object -Value $CommonSwitches[$Key] }
      }
      $VariantSwitches['Custom'] = [string]$CustomSwitch
      $VariantFields['InstallerSwitches'] = $VariantSwitches
      if ($Family -ceq 'Actual Installer' -and $Scope -ceq 'machine') { $VariantFields['ElevationRequirement'] = 'elevatesSelf' }
      $CompleteFields = Merge-WinGetSuggestedManifestFieldSet -Base $ManifestFields -Override $VariantFields
      $Variants.Add((ConvertTo-WinGetSuggestedManifestVariant -Name $Scope -ManifestFields $CompleteFields -Evidence ([ordered]@{ ScopeSwitch = [string]$CustomSwitch })))
    }
  }

  $NextSteps = Get-WinGetSuggestionPropertyValue -InputObject $Template -Name Notes
  [pscustomobject][ordered]@{
    ManifestFields     = [pscustomobject]$ManifestFields
    ManifestVariants   = @($Variants)
    SuggestedNextSteps = [string[]]@($NextSteps)
  }
}

function Get-WinGetDellPassthroughSuggestion {
  <#
  .SYNOPSIS
    Forward known nested family defaults without merging Dell's embedded command.
  .PARAMETER Metadata
    Parsed DUP evidence, including its exact selected nested family and command.
  .OUTPUTS
    Switches and modes for an advisory passthrough route, or no output when
    direct forwarding is unsupported. Raw parser facts are unchanged.
  #>
  param ([Parameter(Mandatory)]$Metadata)

  $Command = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name CommandBehavior
  if ([bool](Get-WinGetSuggestionPropertyValue -InputObject $Command -Name UsesPassthrough)) { return }
  # A configured SFX adds another command-translation layer. Final child
  # switches cannot be sent straight to that outer executable without proof.
  $ExecutionChain = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name ExecutionChain
  if ($ExecutionChain -and @($ExecutionChain).Count -gt 0) { return }
  $Nested = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name NestedInstallerInfo
  $Family = [string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name NestedFamily)
  if (-not $Nested -or -not $Family -or $Family -ceq 'Dell Update Package') { return }
  if ((Get-WinGetSuggestionPropertyValue -InputObject $Nested -Name SupportsSilentInstallation) -eq $false) { return }

  $Wrapper = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name NestedWrapperInfo
  $Behavior = $Wrapper ?? $Nested
  if ((Get-WinGetSuggestionPropertyValue -InputObject $Behavior -Name SupportsSilentInstallation) -eq $false) { return }
  $Type = ConvertTo-WinGetSuggestedInstallerType -InstallerType ([string](Get-WinGetSuggestionPropertyValue -InputObject $Behavior -Name InstallerType))
  $NestedResult = [pscustomobject]@{ Family = $Family; InstallerType = $Type; Metadata = $Behavior; MsiInfo = $Wrapper ? $Nested : $null }
  $Suggestion = Get-WinGetParserResultSuggestion -Result $NestedResult
  $Fields = $Suggestion.ManifestFields
  $Switches = Get-WinGetInstallerDefaultSwitches -InstallerType ($Type ?? 'exe')
  $AuthoredSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Fields -Name InstallerSwitches
  if ($AuthoredSwitches) {
    foreach ($Key in $AuthoredSwitches.Keys) { $Switches[$Key] = [string]$AuthoredSwitches[$Key] }
  }

  # MSI directory switches must come from the selected database, never a
  # generic INSTALLDIR/TARGETDIR placeholder or a suite's hidden MSI parcel.
  $ProjectType = [string](Get-WinGetSuggestionPropertyValue -InputObject $Behavior -Name InstallShieldProjectType)
  $IsInstallShieldMsi = $Family -ceq 'InstallShield' -and $ProjectType -cin @('Basic MSI', 'InstallScript MSI')
  if ($Type -cin @('msi', 'wix') -or $IsInstallShieldMsi) {
    $Location = [string](Get-WinGetSuggestionPropertyValue -InputObject $Nested -Name InstallLocationSwitch)
    if ($Location) { $Switches['InstallLocation'] = $IsInstallShieldMsi ? '/V"' + $Location.Replace('"', '\"') + '"' : $Location }
    else { $Switches.Remove('InstallLocation') }
  }
  if (-not $Switches['Silent']) { return }
  if (-not $Switches['SilentWithProgress']) { $Switches['SilentWithProgress'] = $Switches['Silent'] }
  # Embedded mode tokens, properties and wait flags belong to the alternative
  # MUP route. Mixing them into family defaults can change the requested mode.

  # WinGet appends Log before Custom, so the delimiter must live in each mode
  # switch, including Interactive. All later switches then belong to the vendor.
  foreach ($Mode in @('Silent', 'SilentWithProgress', 'Interactive')) {
    $Switches[$Mode] = ('/passthrough ' + [string]$Switches[$Mode]).TrimEnd()
  }
  $ModeValue = Get-WinGetSuggestionPropertyValue -InputObject $Fields -Name InstallModes
  $Modes = @($ModeValue | Where-Object { $_ })
  if (-not $Modes.Count) {
    $Modes = @('interactive', 'silent')
    if ($Switches['SilentWithProgress'] -cne $Switches['Silent']) { $Modes += 'silentWithProgress' }
  }
  [pscustomobject]@{ InstallerSwitches = $Switches; InstallModes = $Modes }
}

function Get-WinGetParserResultSuggestion {
  <#
  .SYNOPSIS
    Refine family guidance with evidence from one successful parser result.
  .PARAMETER Result
    Provider-neutral successful parser result.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Result)

  $Family = [string](Get-WinGetSuggestionPropertyValue -InputObject $Result -Name Family)
  $Metadata = Get-WinGetSuggestionPropertyValue -InputObject $Result -Name Metadata
  $TemplateFamily = $Family
  $ProjectType = $null
  if ($Family -ceq 'InstallShield' -and $Metadata) {
    $ProjectType = [string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallShieldProjectType)
    if ($ProjectType -ceq 'Advanced UI' -or (Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name Variant) -ceq 'Advanced UI') {
      $TemplateFamily = 'InstallShield Advanced UI'
    } elseif ($ProjectType -cin @('Basic MSI', 'InstallScript MSI')) {
      $TemplateFamily = 'InstallShield MSI Wrapper'
    }
  }
  $Suggestion = Get-WinGetInstallerFamilySuggestion -Family $TemplateFamily
  $Fields = ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Suggestion.ManifestFields
  $Variants = [System.Collections.Generic.List[object]]::new()
  foreach ($Variant in @($Suggestion.ManifestVariants)) { $Variants.Add($Variant) }
  $NextSteps = [System.Collections.Generic.List[string]]::new()
  foreach ($Step in @($Suggestion.SuggestedNextSteps)) { if ($Step) { $NextSteps.Add([string]$Step) } }

  if ($Family -ceq 'MSP') {
    $Fields.Clear()
    $NextSteps.Add('Windows Installer patch packages require target-product validation and are not suggested as standalone installer entries.')
  } else {
    $InstallerType = ConvertTo-WinGetSuggestedInstallerType -InstallerType ([string](Get-WinGetSuggestionPropertyValue -InputObject $Result -Name InstallerType))
    if ($InstallerType) { $Fields['InstallerType'] = $InstallerType }
  }

  $Sources = @($Result, $Metadata, (Get-WinGetSuggestionPropertyValue -InputObject $Result -Name MsiInfo)) | Where-Object { $null -ne $_ }
  foreach ($Source in $Sources) {
    $Scope = [string](Get-WinGetSuggestionPropertyValue -InputObject $Source -Name Scope)
    if ($Scope -cin @('user', 'machine')) { $Fields['Scope'] = $Scope }
    $ProductCode = Get-WinGetSuggestionPropertyValue -InputObject $Source -Name ProductCode
    if (-not [string]::IsNullOrWhiteSpace([string]$ProductCode)) { $Fields['ProductCode'] = [string]$ProductCode }
  }

  foreach ($Field in @('PackageFamilyName', 'SignatureSha256', 'MinimumOSVersion')) {
    foreach ($Source in $Sources) {
      $Value = Get-WinGetSuggestionPropertyValue -InputObject $Source -Name $Field
      if (Test-WinGetSuggestionValue -Value $Value) { $Fields[$Field] = Copy-Object -Value $Value; break }
    }
  }
  foreach ($Field in @('Platform', 'Capabilities', 'RestrictedCapabilities', 'Protocols', 'FileExtensions', 'Dependencies', 'AppsAndFeaturesEntries')) {
    foreach ($Source in $Sources) {
      $Value = Get-WinGetSuggestionPropertyValue -InputObject $Source -Name $Field
      if (Test-WinGetSuggestionValue -Value $Value) { $Fields[$Field] = Copy-Object -Value $Value; break }
    }
  }
  foreach ($Source in $Sources) {
    $Architecture = Get-WinGetSuggestionPropertyValue -InputObject $Source -Name @('PackageArchitecture', 'Architecture', 'RecommendedWinGetArchitecture')
    if ([string]$Architecture -cin @('x86', 'x64', 'arm', 'arm64', 'neutral')) { $Fields['Architecture'] = [string]$Architecture; break }
  }
  foreach ($Source in $Sources) {
    $Location = Get-WinGetSuggestionPropertyValue -InputObject $Source -Name DefaultInstallLocation
    if (-not [string]::IsNullOrWhiteSpace([string]$Location)) {
      $Fields['InstallationMetadata'] = [ordered]@{ DefaultInstallLocation = [string]$Location }
      break
    }
  }

  $GenericBehaviorFamilies = @('Advanced Installer', 'InstallShield', 'InstallShield MSI Wrapper', 'InstallShield Advanced UI', 'Squirrel', 'Velopack', 'Zero Install', 'TigerSetup', 'MicaSetup', 'Kachina', 'Astrum InstallWizard', 'AKInstaller', 'Dell Update Package', 'Setup Factory', 'InstallAnywhere', 'InstallAware', 'Actual Installer', 'DeployMaster', '7z SFX', 'WinRAR GUI SFX', 'InstallMate', 'QSetup', 'install4j', 'dotNetInstaller', 'IExpress', 'Wise', 'InstallBuilder', 'Paquet Builder', 'CreateInstall', 'InstallForge')
  if ($TemplateFamily -cin $GenericBehaviorFamilies -and $Metadata) {
    foreach ($Field in @('InstallModes', 'InstallerSwitches', 'InstallerSuccessCodes', 'ExpectedReturnCodes', 'ElevationRequirement', 'UpgradeBehavior')) {
      $Value = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name $Field
      if (Test-WinGetSuggestionValue -Value $Value) { $Fields[$Field] = Copy-Object -Value $Value }
    }
  }

  if ($Family -ceq 'AKInstaller' -and $Metadata) {
    # Family guidance cannot safely mix modern native, classic native, and MSI
    # bootstrapper command lines. Replace it with the exact route's evidence.
    foreach ($Field in @('InstallModes', 'InstallerSwitches', 'ExpectedReturnCodes')) { $Fields.Remove($Field) }
    $MetadataModes = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallModes
    if (Test-WinGetSuggestionValue -Value $MetadataModes) { $Fields['InstallModes'] = Copy-Object -Value $MetadataModes }
    $MetadataSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallerSwitches
    if (Test-WinGetSuggestionValue -Value $MetadataSwitches) { $Fields['InstallerSwitches'] = Copy-Object -Value $MetadataSwitches }

    # WinGet handles zero as success and cannot use the generic 1603 failure to
    # make a more specific decision. Project only actionable documented codes.
    $DocumentedReturnCodes = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name DocumentedReturnCodes
    $ExpectedReturnCodes = @(
      foreach ($ReturnCode in $DocumentedReturnCodes) {
        $NumericCode = 0
        if (-not [int]::TryParse([string]$ReturnCode, [ref]$NumericCode)) { continue }
        $ReturnResponse = switch ($NumericCode) {
          1602 { 'cancelledByUser' }
          1618 { 'installInProgress' }
          1625 { 'blockedByPolicy' }
          1638 { 'alreadyInstalled' }
          3010 { 'rebootRequiredToFinish' }
          1641 { 'rebootInitiated' }
          default { $null }
        }
        if ($ReturnResponse) { [ordered]@{ InstallerReturnCode = $NumericCode; ReturnResponse = $ReturnResponse } }
      }
    )
    if ($ExpectedReturnCodes.Count -gt 0) { $Fields['ExpectedReturnCodes'] = $ExpectedReturnCodes }
  }

  if ($Family -ceq 'TigerSetup' -and $Metadata) {
    $Fields['ExpectedReturnCodes'] = @(
      foreach ($Code in @(@(1, 'custom'), @(2, 'invalidParameter'), @(3, 'missingDependency'), @(4, 'custom'), @(5, 'cancelledByUser'), @(6, 'packageInUseByApplication'), @(7, 'custom'), @(8, 'systemNotSupported'), @(3010, 'rebootRequiredToFinish'))) {
        [ordered]@{ InstallerReturnCode = $Code[0]; ReturnResponse = $Code[1] }
      }
    )
  }

  if ($Family -ceq 'Dell Update Package' -and $Metadata) {
    # Both routes execute the outer DUP, which maps vendor outcomes to its own
    # process status rather than propagating the nested installer's code.
    $Fields['ExpectedReturnCodes'] = @(
      [ordered]@{ InstallerReturnCode = 2; ReturnResponse = 'rebootRequiredToFinish' }
      [ordered]@{ InstallerReturnCode = 4; ReturnResponse = 'missingDependency' }
      [ordered]@{ InstallerReturnCode = 5; ReturnResponse = 'systemNotSupported' }
      [ordered]@{ InstallerReturnCode = 6; ReturnResponse = 'rebootInitiated' }
    )
    $Passthrough = Get-WinGetDellPassthroughSuggestion -Metadata $Metadata
    if ($Passthrough) {
      # Preserve the complete original switch route separately. Evidence retains
      # the literal vendor command for a focused, manually validated fallback.
      $EmbeddedSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Fields -Name InstallerSwitches
      if (Get-WinGetSuggestionPropertyValue -InputObject $EmbeddedSwitches -Name Silent) {
        $Command = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name CommandBehavior
        $Variants.Add((ConvertTo-WinGetSuggestedManifestVariant -Name EmbeddedMup -ManifestFields $Fields -Evidence ([ordered]@{
                CommandSource   = 'MupUnattended'
                VendorArguments = [string]((Get-WinGetSuggestionPropertyValue -InputObject $Command -Name DefaultVendorArguments) ?? (Get-WinGetSuggestionPropertyValue -InputObject $Command -Name VendorArguments))
              })))
      }
      $Fields['InstallerSwitches'] = $Passthrough.InstallerSwitches
      $Fields['InstallModes'] = $Passthrough.InstallModes
      $NextSteps.Add('Prefer the suggested family-default /passthrough route without merging embedded MUP arguments. If VM validation fails, inspect the EmbeddedMup variant and its VendorArguments for only the required package-specific options, or test the complete /s fallback. Reanalyze every changed command and validate its modes, vendor log, location, ARP and exit codes; raw parser metadata still describes the embedded command.')
    }
  }

  if ($Family -ceq 'Setup Factory' -and $Metadata) {
    $SilentSupport = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name SupportsSilentInstallation
    if ($null -eq $SilentSupport) {
      $NextSteps.Add('The Setup Factory silent-mode project setting is unresolved for this artifact; do not add /S until unattended installation is validated in a VM.')
    } elseif (-not [bool]$SilentSupport) {
      $NextSteps.Add('This Setup Factory artifact is interactive-only because its generation predates silent mode or its compiled project disables the feature; do not add /S.')
    }
  }

  if ($Family -ceq 'DeployMaster' -and $Metadata) {
    # Family-only guidance describes locator-based DeployMaster media. Exact parser evidence must
    # replace those defaults because classic 2.x runtimes are proven interactive-only and expose
    # neither /silent nor /appfolder.
    foreach ($Field in @('InstallModes', 'InstallerSwitches')) { $Fields.Remove($Field) }
    $MetadataModes = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallModes
    if (Test-WinGetSuggestionValue -Value $MetadataModes) { $Fields['InstallModes'] = Copy-Object -Value $MetadataModes }
    $MetadataSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallerSwitches
    if (Test-WinGetSuggestionValue -Value $MetadataSwitches) { $Fields['InstallerSwitches'] = Copy-Object -Value $MetadataSwitches }

    if ([bool](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name SupportsDualScope)) {
      $NextSteps.Add('This DeployMaster artifact supports both user and machine installation. Do not create scope variants until an explicit current-user selector is validated for this runtime; elevation alone can change the selected scope.')
    }
  }

  if ($Family -ceq 'Zero Install' -and $Metadata) {
    # The family template describes current application bootstrappers. Exact
    # parser evidence must remove those defaults for generic or historical
    # launchers that predate silent, machine-scope, or store-path switches.
    foreach ($Field in @('Scope', 'ProductCode', 'InstallModes', 'InstallerSwitches', 'AppsAndFeaturesEntries')) { $Fields.Remove($Field) }
    $MetadataScope = [string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name Scope)
    if ($MetadataScope -cin @('user', 'machine')) { $Fields['Scope'] = $MetadataScope }
    $MetadataProductCode = [string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name ProductCode)
    if (-not [string]::IsNullOrWhiteSpace($MetadataProductCode)) { $Fields['ProductCode'] = $MetadataProductCode }
    $MetadataModes = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallModes
    if (Test-WinGetSuggestionValue -Value $MetadataModes) { $Fields['InstallModes'] = Copy-Object -Value $MetadataModes }
    $MetadataSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallerSwitches
    if (Test-WinGetSuggestionValue -Value $MetadataSwitches) { $Fields['InstallerSwitches'] = Copy-Object -Value $MetadataSwitches }
    $MetadataArp = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name AppsAndFeaturesEntries
    if (Test-WinGetSuggestionValue -Value $MetadataArp) { $Fields['AppsAndFeaturesEntries'] = Copy-Object -Value $MetadataArp }
    if ([string]::IsNullOrWhiteSpace([string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name AppUri))) { $Fields.Remove('UpgradeBehavior') }
  }

  $MetadataVariant = if ($Metadata) { [string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name Variant) } else { $null }
  if ($Family -ceq 'InstallShield' -and ($MetadataVariant -ceq 'InstallScript' -or $ProjectType -ceq 'InstallScript')) {
    $Fields['InstallModes'] = @('interactive')
    $Fields.Remove('InstallerSwitches')
    $InstallScriptInfo = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallScriptInfo
    $SilentSupport = [string](Get-WinGetSuggestionPropertyValue -InputObject $InstallScriptInfo -Name SilentSupport)
    if ($SilentSupport -ceq 'Supported') {
      $Fields['InstallModes'] = @('interactive', 'silent')
      $Fields['InstallerSwitches'] = [ordered]@{ Silent = '/s' }
    } else {
      $NextSteps.Add("InstallShield InstallScript silent-support result is '$SilentSupport'; response-file-dependent media is not WinGet-compatible.")
    }
  }

  if ($Family -ceq 'dotNetInstaller' -and $Metadata) {
    # The outer runtime may accept /q or /qb while a selected nested component
    # falls back to its full command. Suggest only modes proven across the
    # default component routes; retain outer capabilities on the parser result.
    $NestedModeValue = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name NestedInstallModes
    $NestedModes = @(if (Test-WinGetSuggestionValue -Value $NestedModeValue) { $NestedModeValue })
    if ($NestedModes.Count -gt 0) { $Fields['InstallModes'] = $NestedModes }
    $Switches = Get-WinGetSuggestionPropertyValue -InputObject $Fields -Name InstallerSwitches
    if ($NestedModes.Count -gt 0 -and $Switches -is [Collections.IDictionary]) {
      $FilteredSwitches = [ordered]@{}
      foreach ($Key in $Switches.Keys) {
        if ($Key -ceq 'Silent' -and $NestedModes -notcontains 'silent') { continue }
        if ($Key -ceq 'SilentWithProgress' -and $NestedModes -notcontains 'silentWithProgress') { continue }
        $FilteredSwitches[$Key] = Copy-Object -Value $Switches[$Key]
      }
      if ($FilteredSwitches.Count -gt 0) { $Fields['InstallerSwitches'] = $FilteredSwitches } else { $Fields.Remove('InstallerSwitches') }
    }
  }

  if ($Family -ceq 'Qt Installer Framework' -and $Metadata) {
    $Fields['InstallerType'] = 'exe'
    $SupportsSilentInstallation = [bool](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name SupportsSilentInstallation)
    if (-not $SupportsSilentInstallation) {
      $Fields['InstallModes'] = @('interactive')
      $Fields.Remove('InstallerSwitches')
      $NextSteps.Add('This Qt IFW launcher is GUI-only or has its command-line interface disabled; do not author silent switches.')
    } else {
      $Fields['InstallModes'] = @('interactive', 'silent', 'silentWithProgress')
      if ([bool](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name RequiresExplicitInstallLocation)) {
        $Command = 'install --root "<INSTALLPATH>" --accept-licenses --default-answer --confirm-command'
        $Fields['InstallerSwitches'] = [ordered]@{ Silent = $Command; SilentWithProgress = $Command }
      } else {
        $Command = 'install --accept-licenses --default-answer --confirm-command'
        $Fields['InstallerSwitches'] = [ordered]@{ Silent = $Command; SilentWithProgress = $Command; InstallLocation = '--root "<INSTALLPATH>"' }
      }
    }
    $RecommendedUpgradeBehavior = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name RecommendedUpgradeBehavior
    if ($RecommendedUpgradeBehavior) { $Fields['UpgradeBehavior'] = $RecommendedUpgradeBehavior }
  }

  if ($Family -ceq 'Astrum InstallWizard' -and $Metadata) {
    $SupportsSilentInstallation = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name SupportsSilentInstallation
    if ($SupportsSilentInstallation -eq $true) {
      $Fields['InstallModes'] = @('interactive', 'silent')
      $Fields['InstallerSwitches'] = Copy-Object -Value (Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallerSwitches)
      $SuccessCodes = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallerSuccessCodes
      if (Test-WinGetSuggestionValue -Value $SuccessCodes) { $Fields['InstallerSuccessCodes'] = Copy-Object -Value $SuccessCodes }
    } elseif ($SupportsSilentInstallation -eq $false) {
      $Fields['InstallModes'] = @('interactive')
      $Fields.Remove('InstallerSwitches')
      $NextSteps.Add('The compiled Astrum User Information dialog prevents /silent from completing; treat this artifact as interactive-only.')
    } else {
      $Fields.Remove('InstallModes')
      $Fields.Remove('InstallerSwitches')
      $Fields.Remove('InstallerSuccessCodes')
      $NextSteps.Add('Determine the Astrum 1.x builder subversion or validate /silent and the success exit code in a VM before adding unattended-installation fields.')
    }
  }

  if ($Family -ceq 'Chromium Setup' -and $Metadata) {
    $Fields = ConvertTo-WinGetSuggestedManifestFieldSet -InputObject ([ordered]@{ InstallerType = 'exe' })
    switch ([string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name Variant)) {
      'ChromiumMiniInstaller' {
        $Fields['InstallModes'] = @('silent')
        $Fields['InstallerSwitches'] = [ordered]@{ Custom = '--do-not-launch-chrome'; Log = '--verbose-logging --log-file="<LOGPATH>"' }
      }
      'ChromiumUpdater' {
        if (-not [bool](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name IsOnlineBootstrapper)) {
          $Fields['InstallModes'] = @('interactive', 'silent')
          $Fields['InstallerSwitches'] = [ordered]@{ Silent = '--install --silent'; SilentWithProgress = '--install --silent'; Interactive = '--install'; Log = '--enable-logging'; Upgrade = '--update' }
        } else {
          $NextSteps.Add('This Chromium Updater is an online application bootstrapper; validate the target package and vendor-specific switches.')
        }
      }
      'Omaha' {
        $UpdaterTag = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name UpdaterTag
        $IsTagged = [bool](Get-WinGetSuggestionPropertyValue -InputObject $UpdaterTag -Name IsTagged)
        if (-not [bool](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name IsOnlineBootstrapper) -and -not $IsTagged) {
          $Fields['InstallModes'] = @('silent')
          $Fields['InstallerSwitches'] = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/silent' }
        } elseif (Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name OfflineManifest) {
          $NextSteps.Add('This tagged Omaha package contains an offline target payload; preserve its package-specific action and switches.')
        } else {
          $NextSteps.Add('This tagged Omaha setup is an application bootstrapper; expand the payload and validate final ARP and switches.')
        }
      }
    }
  }

  $ScopeSwitches = if ($Metadata) { Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name ScopeSwitches } else { $null }
  if (-not $ScopeSwitches -and $Metadata -and [bool](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name SupportsDualScope)) {
    $ScopeSwitches = [pscustomobject]@{
      User    = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name UserScopeSwitch
      Machine = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name MachineScopeSwitch
    }
  }
  $ScopeInstallLocationSwitches = if ($Metadata) { Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name ScopeInstallLocationSwitches } else { $null }
  # Generic family guidance advertises every documented scope route. Once an
  # Actual Installer artifact has been parsed, discard those generic variants
  # and rebuild only the routes allowed by its compiled InstallLevel.
  if ($Family -ceq 'Actual Installer' -and $Metadata) { $Variants.Clear() }
  if ($ScopeSwitches) {
    $Variants.Clear()
    foreach ($Scope in @('user', 'machine')) {
      $CustomSwitch = Get-WinGetSuggestionPropertyValue -InputObject $ScopeSwitches -Name ($Scope -eq 'user' ? 'User' : 'Machine')
      $SupportedScopeValue = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name SupportedScopes
      $SupportedScopes = @($SupportedScopeValue)
      if ($SupportedScopes.Count -gt 0 -and $Scope -notin $SupportedScopes) { continue }
      $Override = [ordered]@{ Scope = $Scope }
      if ($Family -ceq 'Kachina' -and $Scope -ceq 'user') { $Override['ElevationRequirement'] = $null }
      if ($Family -ceq 'TigerSetup') {
        $Override['ElevationRequirement'] = $Scope -ceq 'machine' ? 'elevatesSelf' : $null
        $Locations = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name InstallLocations
        $Location = Get-WinGetSuggestionPropertyValue -InputObject $Locations -Name $Scope
        if ($Location) { $Override['InstallationMetadata'] = [ordered]@{ DefaultInstallLocation = $Location } }
      }
      if (-not [string]::IsNullOrWhiteSpace([string]$CustomSwitch)) {
        $Switches = [ordered]@{}
        $CommonSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Fields -Name InstallerSwitches
        if ($CommonSwitches -is [System.Collections.IDictionary]) {
          foreach ($Key in $CommonSwitches.Keys) { $Switches[$Key] = Copy-Object -Value $CommonSwitches[$Key] }
        }
        $ScopeInstallLocation = Get-WinGetSuggestionPropertyValue -InputObject $ScopeInstallLocationSwitches -Name ($Scope -eq 'user' ? 'User' : 'Machine')
        if (-not [string]::IsNullOrWhiteSpace([string]$ScopeInstallLocation)) { $Switches['InstallLocation'] = [string]$ScopeInstallLocation }
        $VariantCustomSwitch = [string]$CustomSwitch
        if ($Family -ceq 'Chromium Setup') {
          $ChromiumVariant = [string](Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name Variant)
          $ChromiumTag = Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name UpdaterTag
          $ChromiumIsTagged = [bool](Get-WinGetSuggestionPropertyValue -InputObject $ChromiumTag -Name IsTagged)
          if ($ChromiumVariant -ceq 'ChromiumMiniInstaller' -and -not [string]::IsNullOrWhiteSpace([string]$Switches['Custom'])) {
            $VariantCustomSwitch = "$($Switches['Custom']) $VariantCustomSwitch"
          } elseif ($ChromiumVariant -ceq 'ChromiumUpdater' -and -not $ChromiumIsTagged) {
            $VariantCustomSwitch = $Scope -ceq 'user' ? '--enterprise' : "$VariantCustomSwitch --enterprise"
          }
        }
        $Switches['Custom'] = $VariantCustomSwitch
        $Override['InstallerSwitches'] = $Switches
      } elseif ($Family -ceq 'Chromium Setup' -and (Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name Variant) -ceq 'ChromiumUpdater' -and -not [bool](Get-WinGetSuggestionPropertyValue -InputObject (Get-WinGetSuggestionPropertyValue -InputObject $Metadata -Name UpdaterTag) -Name IsTagged)) {
        $Switches = [ordered]@{}
        $CommonSwitches = Get-WinGetSuggestionPropertyValue -InputObject $Fields -Name InstallerSwitches
        if ($CommonSwitches -is [System.Collections.IDictionary]) {
          foreach ($Key in $CommonSwitches.Keys) { $Switches[$Key] = Copy-Object -Value $CommonSwitches[$Key] }
        }
        $Switches['Custom'] = '--enterprise'
        $Override['InstallerSwitches'] = $Switches
      }
      $CompleteFields = Merge-WinGetSuggestedManifestFieldSet -Base $Fields -Override $Override
      $Variants.Add((ConvertTo-WinGetSuggestedManifestVariant -Name $Scope -ManifestFields $CompleteFields -Evidence ([ordered]@{ ScopeSwitch = $CustomSwitch })))
    }
  }

  $SuggestedArchitectures = @(
    foreach ($Source in $Sources) {
      $ArchitectureValue = Get-WinGetSuggestionPropertyValue -InputObject $Source -Name @('RecommendedWinGetArchitectures', 'SupportedArchitectures', 'PayloadArchitectures', 'Architectures')
      foreach ($Architecture in @($ArchitectureValue)) {
        if ([string]$Architecture -cin @('x86', 'x64', 'arm', 'arm64')) { [string]$Architecture }
      }
    }
  ) | Select-Object -Unique
  if (-not $Fields.Contains('Architecture') -and $SuggestedArchitectures.Count -eq 1) {
    $Fields['Architecture'] = $SuggestedArchitectures[0]
    for ($Index = 0; $Index -lt $Variants.Count; $Index++) {
      $Variant = $Variants[$Index]
      $VariantFields = Merge-WinGetSuggestedManifestFieldSet -Base (ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Variant.ManifestFields) -Override ([ordered]@{ Architecture = $SuggestedArchitectures[0] })
      $Variants[$Index] = ConvertTo-WinGetSuggestedManifestVariant -Name $Variant.Name -ManifestFields $VariantFields -Evidence $Variant.Evidence
    }
  } elseif (-not $Fields.Contains('Architecture') -and $SuggestedArchitectures.Count -gt 1) {
    $BaseVariants = @($Variants)
    $Variants.Clear()
    if ($BaseVariants.Count -eq 0) {
      foreach ($Architecture in $SuggestedArchitectures) {
        $VariantFields = Merge-WinGetSuggestedManifestFieldSet -Base $Fields -Override ([ordered]@{ Architecture = $Architecture })
        $Variants.Add((ConvertTo-WinGetSuggestedManifestVariant -Name $Architecture -ManifestFields $VariantFields -Evidence ([ordered]@{ Architecture = $Architecture })))
      }
    } else {
      foreach ($BaseVariant in $BaseVariants) {
        foreach ($Architecture in $SuggestedArchitectures) {
          $VariantFields = Merge-WinGetSuggestedManifestFieldSet -Base (ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $BaseVariant.ManifestFields) -Override ([ordered]@{ Architecture = $Architecture })
          $Variants.Add((ConvertTo-WinGetSuggestedManifestVariant -Name "$($BaseVariant.Name)-$Architecture" -ManifestFields $VariantFields -Evidence ([ordered]@{ VariantEvidence = $BaseVariant.Evidence; Architecture = $Architecture })))
        }
      }
    }
  }

  [pscustomobject][ordered]@{
    ManifestFields     = [pscustomobject](ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Fields)
    ManifestVariants   = @($Variants)
    SuggestedNextSteps = [string[]]@($NextSteps | Select-Object -Unique)
  }
}

function Get-WinGetPortableAnalysisSuggestion {
  <#
  .SYNOPSIS
    Project portable PE architecture and runtime dependency evidence to WinGet suggestions.
  .PARAMETER PortableEvidence
    Provider-neutral PE evidence returned by Get-InstallerAnalysis.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$PortableEvidence)

  $Fields = [ordered]@{ InstallerType = 'portable' }
  $Architectures = @($PortableEvidence.RecommendedWinGetArchitectures | Where-Object { [string]$_ -cin @('x86', 'x64', 'arm', 'arm64') } | Select-Object -Unique)
  if ($Architectures.Count -eq 1) { $Fields['Architecture'] = $Architectures[0] }
  $Dependencies = @($PortableEvidence.RecommendedPackageDependencies | Where-Object { $null -ne $_ })
  if ($Dependencies.Count -gt 0) { $Fields['Dependencies'] = [ordered]@{ PackageDependencies = $Dependencies } }
  $Fields = ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Fields
  $Variants = [System.Collections.Generic.List[object]]::new()
  if ($Architectures.Count -gt 1) {
    foreach ($Architecture in $Architectures) {
      $VariantFields = Merge-WinGetSuggestedManifestFieldSet -Base $Fields -Override ([ordered]@{ Architecture = $Architecture })
      $Variants.Add((ConvertTo-WinGetSuggestedManifestVariant -Name $Architecture -ManifestFields $VariantFields -Evidence ([ordered]@{ Architecture = $Architecture })))
    }
  }

  [pscustomobject][ordered]@{
    ManifestFields     = [pscustomobject]$Fields
    ManifestVariants   = @($Variants)
    SuggestedNextSteps = @('Confirm that the selected PE is a portable command target; DLL analysis alone does not make a DLL installable.')
  }
}

function Add-WinGetInstallerProjection {
  <#
  .SYNOPSIS
    Add schema-valid WinGet suggestions to provider-neutral analyzer evidence.
  .PARAMETER InputObject
    Generic analyzer result whose family records should receive WinGet policy.
  #>
  param ([Parameter(Mandatory)][object]$InputObject)

  $PrimarySuggestion = $null
  foreach ($ParserRun in @($InputObject.ParserResults | Where-Object { $_.Success -and $_.Result })) {
    $Suggestion = Get-WinGetParserResultSuggestion -Result $ParserRun.Result
    if (-not $PrimarySuggestion) { $PrimarySuggestion = $Suggestion }
    $ParserRun.Result | Add-Member -NotePropertyName SuggestedManifestFields -NotePropertyValue $Suggestion.ManifestFields -Force
    $ParserRun.Result | Add-Member -NotePropertyName SuggestedManifestVariants -NotePropertyValue @($Suggestion.ManifestVariants) -Force
    $ParserRun.Result | Add-Member -NotePropertyName SuggestedNextSteps -NotePropertyValue @($Suggestion.SuggestedNextSteps) -Force
    $InputObject.SuggestedNextSteps = @($InputObject.SuggestedNextSteps + $Suggestion.SuggestedNextSteps | Select-Object -Unique)
  }

  foreach ($FamilyEvidence in @($InputObject.DetectedFamilies)) {
    $ParserRun = @($InputObject.ParserResults | Where-Object {
        $_.Success -and $_.Result -and (
          $_.Name -ceq $FamilyEvidence.ParserName -or
          [string](Get-WinGetSuggestionPropertyValue -InputObject $_.Result -Name Family) -ceq $FamilyEvidence.Family
        )
      } | Select-Object -First 1)[0]
    $Suggestion = if ($ParserRun) { Get-WinGetParserResultSuggestion -Result $ParserRun.Result } else { Get-WinGetInstallerFamilySuggestion -Family $FamilyEvidence.Family }
    if (-not $PrimarySuggestion) { $PrimarySuggestion = $Suggestion }
    $FamilyEvidence | Add-Member -NotePropertyName SuggestedManifestFields -NotePropertyValue $Suggestion.ManifestFields -Force
    $FamilyEvidence | Add-Member -NotePropertyName SuggestedManifestVariants -NotePropertyValue @($Suggestion.ManifestVariants) -Force
    $FamilyEvidence | Add-Member -NotePropertyName SuggestedNextSteps -NotePropertyValue @($Suggestion.SuggestedNextSteps) -Force
  }

  foreach ($RoutingHint in @($InputObject.RoutingHints)) {
    $Suggestion = Get-WinGetInstallerFamilySuggestion -Family $RoutingHint.Family
    if (-not $PrimarySuggestion) { $PrimarySuggestion = $Suggestion }
    $RoutingHint | Add-Member -NotePropertyName SuggestedManifestFields -NotePropertyValue $Suggestion.ManifestFields -Force
    $RoutingHint | Add-Member -NotePropertyName SuggestedManifestVariants -NotePropertyValue @($Suggestion.ManifestVariants) -Force
    $RoutingHint | Add-Member -NotePropertyName SuggestedNextSteps -NotePropertyValue @($Suggestion.SuggestedNextSteps) -Force
  }

  if (-not $PrimarySuggestion -and $InputObject.PortableEvidence) {
    $PrimarySuggestion = Get-WinGetPortableAnalysisSuggestion -PortableEvidence $InputObject.PortableEvidence
  }
  if (-not $PrimarySuggestion) {
    $PrimarySuggestion = [pscustomobject][ordered]@{ ManifestFields = [pscustomobject][ordered]@{}; ManifestVariants = @(); SuggestedNextSteps = @() }
  }
  $InputObject | Add-Member -NotePropertyName SuggestedManifestFields -NotePropertyValue $PrimarySuggestion.ManifestFields -Force
  $InputObject | Add-Member -NotePropertyName SuggestedManifestVariants -NotePropertyValue @($PrimarySuggestion.ManifestVariants) -Force
  $InputObject.SuggestedNextSteps = @($InputObject.SuggestedNextSteps + $PrimarySuggestion.SuggestedNextSteps | Select-Object -Unique)

  $InputObject.FamilyCandidates = @($InputObject.DetectedFamilies)
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
  .PARAMETER CommandLine
    Virtual command line for NSIS simulation and Dell vendor argument routing.
  .OUTPUTS
    Analyzer evidence with SuggestedManifestFields, SuggestedManifestVariants,
    and SuggestedNextSteps. Variants contain Name, ManifestFields and Evidence.
    Dell's EmbeddedMup variant keeps wrapper switches and literal vendor
    arguments separate from the preferred family-default passthrough route.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$Path,
    [ValidateRange(4096, 268435456)][int64]$ScanBytes = 16777216,
    [switch]$ExtractEmbeddedMsi,
    [AllowEmptyString()][string]$CommandLine = ''
  )
  process {
    $Result = Get-InstallerAnalysis -Path $Path -ScanBytes $ScanBytes -ExtractEmbeddedMsi:$ExtractEmbeddedMsi -CommandLine $CommandLine
    Add-WinGetInstallerProjection -InputObject $Result
  }
}

Export-ModuleMember -Function Get-WinGetInstallerAnalysis
