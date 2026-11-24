. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global
}

Describe 'dotNetInstaller configuration parser' {
  It 'Returns each UI-mode command and resolves the embedded MSI' {
    $Content = @'
<?xml version="1.0" encoding="utf-8"?>
<configurations fileversion="1.2.3.4" productversion="1.2.3">
  <schema version="3.1.113.0" generator="dotNetInstaller InstallerEditor" />
  <configuration type="install" os_filter_min="win7" processor_architecture_filter="x64">
    <component type="msi" id="runtime" display_name="Runtime" package="#CABPATH\SupportFiles\Runtime.msi"
      cmdparameters="/qb-" cmdparameters_basic="/passive" cmdparameters_silent="/qn /norestart"
      selected_install="True" required_install="True" supports_install="True" processor_architecture_filter="x64" />
  </configuration>
</configurations>
'@
    $Result = ConvertFrom-DotNetInstallerConfiguration -Content $Content -ArchiveEntry @('SupportFiles\Runtime.msi')
    $Component = $Result.Components[0]

    $Result.ProductVersion | Should -Be '1.2.3'
    $Result.Generator | Should -Be 'dotNetInstaller InstallerEditor'
    $Component.Type | Should -Be 'msi'
    $Component.ProcessorArchitectureFilter | Should -Be 'x64'
    $Component.Commands.Count | Should -Be 3
    $Component.Commands[2].Mode | Should -Be 'Silent'
    $Component.Commands[2].Command.ExecutedPayload | Should -Be 'SupportFiles\Runtime.msi'
    $Component.Commands[2].Command.ArgumentList | Should -Be @('/qn', '/norestart')
  }

  It 'Uses source-accurate basic and silent fallback order' {
    $Content = @'
<configurations>
  <configuration type="install">
    <component type="exe" id="runtime" executable="setup.exe" exeparameters="/full" exeparameters_silent="/quiet" />
  </configuration>
</configurations>
'@
    $Result = ConvertFrom-DotNetInstallerConfiguration -Content $Content -ArchiveEntry @('setup.exe')

    $Result.Components[0].Commands[0].Command.ArgumentList | Should -Be @('/full')
    $Result.Components[0].Commands[1].Command.ArgumentList | Should -Be @('/quiet')
    $Result.Components[0].Commands[2].Command.ArgumentList | Should -Be @('/quiet')
  }

  It 'Parses legacy grouped collections and the openfile file attribute' {
    $Content = @'
<configurations fileversion="1.4.0.0" productversion="1.0">
  <schema version="1" />
  <configuration type="install" administrator_required="True" lcid="1033" os_filter_greater="29" os_filter_smaller="90">
    <components>
      <component type="openfile" description="Read me" file="#CABPATH\docs\readme.txt" required="False" selected="False" os_filter_greater="44" os_filter_smaller="90">
        <embedfiles><embedfile sourcefilepath="readme.txt" targetfilepath="docs\readme.txt" /></embedfiles>
      </component>
    </components>
    <embedfiles><embedfile sourcefilepath="global.txt" targetfilepath="global.txt" /></embedfiles>
  </configuration>
</configurations>
'@
    $Result = ConvertFrom-DotNetInstallerConfiguration -Content $Content -ArchiveEntry @('docs\readme.txt', 'global.txt')

    $Result.XmlStorageRoute | Should -Be 'GroupedCollections'
    $Result.Components.Count | Should -Be 1
    $Result.Components[0].EmbeddedFiles.Count | Should -Be 1
    $Result.Configurations[0].EmbeddedFiles.Count | Should -Be 1
    $Result.Configurations[0].LcidFilter | Should -Be '1033'
    $Result.Configurations[0].LegacyOsFilterGreater | Should -Be '29'
    $Result.Components[0].Id | Should -Be 'Read me'
    $Result.Components[0].DisplayName | Should -Be 'Read me'
    $Result.Components[0].RequiredInstall | Should -BeFalse
    $Result.Components[0].SelectedInstall | Should -BeFalse
    $Result.Components[0].LegacyOsFilterSmaller | Should -Be '90'
    $Result.Components[0].Commands[0].RawCommandLine | Should -Be '#CABPATH\docs\readme.txt'
    $Result.Components[0].Commands[0].Command.ExecutedPayload | Should -Be 'docs\readme.txt'
  }

  It 'Retains reference configurations and download destinations' {
    $Content = @'
<configurations>
  <configuration type="reference">
    <configfile filename="#TEMPPATH\remote.xml" />
    <downloaddialog><downloads><download sourceurl="https://example.test/remote.xml" destinationpath="#TEMPPATH" /></downloads></downloaddialog>
  </configuration>
  <configuration type="install">
    <component type="cmd" id="payload" command="#TEMPPATH\setup.exe">
      <downloaddialog><download sourceurl="https://example.test/setup.exe" destinationpath="#TEMPPATH" /></downloaddialog>
    </component>
  </configuration>
</configurations>
'@
    $Result = ConvertFrom-DotNetInstallerConfiguration -Content $Content

    $Result.References[0].FileName | Should -Be '#TEMPPATH\remote.xml'
    $Result.Downloads.Count | Should -Be 2
    $Result.Components[0].Downloads[0].Destination | Should -Be '#TEMPPATH\setup.exe'
  }

  It 'Merges supplied reference configurations with global indices and provenance' {
    $PayloadPath = Join-Path $TestDrive 'payloads\x64\setup.msi'
    $ReferencePath = Join-Path $TestDrive 'references\child.xml'
    $null = New-Item -Path (Split-Path $PayloadPath -Parent) -ItemType Directory -Force
    $null = New-Item -Path (Split-Path $ReferencePath -Parent) -ItemType Directory -Force
    [IO.File]::WriteAllBytes($PayloadPath, [byte[]]@(0))
    [IO.File]::WriteAllText($ReferencePath, @'
<configurations productversion="2.0">
  <schema version="3.2.115.0" generator="reference" />
  <configuration type="install" processor_architecture_filter="x64">
    <component type="msi" id="sidecar" package="#TEMPPATH\setup.msi" cmdparameters_silent="/qn" />
  </configuration>
</configurations>
'@)
    $Primary = ConvertFrom-DotNetInstallerConfiguration -Content @'
<configurations productversion="1.0">
  <schema version="3.2.115.0" generator="primary" />
  <configuration type="reference">
    <configfile filename="#TEMPPATH\child.xml" />
  </configuration>
</configurations>
'@ -ConfigurationSource 'PE:CUSTOM/RES_CONFIGURATION'

    $Resolution = InModuleScope DotNetInstaller -Parameters @{
      Primary       = $Primary
      ReferencePath = $ReferencePath
      PayloadPath   = $PayloadPath
    } {
      param ($Primary, $ReferencePath, $PayloadPath)
      Resolve-DotNetInstallerConfigurationSet -PrimaryConfiguration $Primary -ReferenceFile @(Get-Item $ReferencePath) -ArchiveEntry @($PayloadPath)
    }

    $Resolution.Configuration.ConfigurationDocuments.Count | Should -Be 2
    $Resolution.Configuration.Configurations.Index | Should -Be @(0, 1)
    $Resolution.Configuration.Components.Count | Should -Be 1
    $Resolution.Configuration.Components[0].ConfigurationSource | Should -Be $ReferencePath
    $Resolution.Configuration.Components[0].ReferenceDepth | Should -Be 1
    $Resolution.Configuration.Components[0].Commands[2].Command.ExecutedPayload | Should -Be $PayloadPath
    $Resolution.Configuration.References[0].ResolutionStatus | Should -Be 'Resolved'
    $Resolution.Configuration.UnresolvedReferences | Should -BeNullOrEmpty
    $Resolution.Configuration.HasReferenceRisk | Should -BeFalse
  }

  It 'Rejects a cyclic supplied reference at the runtime depth boundary' {
    $ReferencePath = Join-Path $TestDrive 'cycle.xml'
    [IO.File]::WriteAllText($ReferencePath, @'
<configurations>
  <schema version="3.2.115.0" />
  <configuration type="reference"><configfile filename="#TEMPPATH\cycle.xml" /></configuration>
</configurations>
'@)
    $Primary = ConvertFrom-DotNetInstallerConfiguration -Content @'
<configurations>
  <schema version="3.2.115.0" />
  <configuration type="reference"><configfile filename="#TEMPPATH\cycle.xml" /></configuration>
</configurations>
'@ -ConfigurationSource 'PE:CUSTOM/RES_CONFIGURATION'

    $Resolution = InModuleScope DotNetInstaller -Parameters @{ Primary = $Primary; ReferencePath = $ReferencePath } {
      param ($Primary, $ReferencePath)
      Resolve-DotNetInstallerConfigurationSet -PrimaryConfiguration $Primary -ReferenceFile @(Get-Item $ReferencePath)
    }

    $Resolution.Configuration.ConfigurationDocuments.Count | Should -Be 2
    $Resolution.Configuration.UnresolvedReferences.Count | Should -Be 1
    $Resolution.Configuration.HasReferenceRisk | Should -BeTrue
    $Resolution.Diagnostics.Id | Should -Contain 'DotNetInstaller.Configuration.ReferenceCycle'
  }

  It 'Reports a missing supplied reference as unresolved installability evidence' {
    $Primary = ConvertFrom-DotNetInstallerConfiguration -Content @'
<configurations>
  <schema version="3.2.115.0" />
  <configuration type="reference"><configfile filename="#TEMPPATH\missing.xml" /></configuration>
</configurations>
'@ -ConfigurationSource 'PE:CUSTOM/RES_CONFIGURATION'

    $Resolution = InModuleScope DotNetInstaller -Parameters @{ Primary = $Primary } {
      param ($Primary)
      Resolve-DotNetInstallerConfigurationSet -PrimaryConfiguration $Primary
    }

    $Resolution.Configuration.UnresolvedReferences.Count | Should -Be 1
    $Resolution.Configuration.References[0].ResolutionStatus | Should -Be 'Missing'
    $Resolution.Configuration.HasReferenceRisk | Should -BeTrue
    $Resolution.Diagnostics.Id | Should -Contain 'DotNetInstaller.Configuration.ReferenceMissing'
  }

  It 'Keeps cabinet and sidecar command namespaces separate' {
    InModuleScope DotNetInstaller {
      $CompanionPath = 'C:\package\setup.msi'

      Get-DotNetInstallerCommandCandidatePath -CommandLine '#CABPATH\setup.msi' -EmbeddedPath @() -CompanionPath $CompanionPath | Should -BeNullOrEmpty
      Get-DotNetInstallerCommandCandidatePath -CommandLine '#TEMPPATH\setup.msi' -EmbeddedPath @('setup.msi') -CompanionPath $CompanionPath | Should -Be @($CompanionPath)
    }
  }

  It 'Prefers a relative-path suffix over duplicate basenames and reports schema drift' {
    $PreferredPath = Join-Path $TestDrive 'preferred\config\child.xml'
    $OtherPath = Join-Path $TestDrive 'other\child.xml'
    $null = New-Item -Path (Split-Path $PreferredPath -Parent) -ItemType Directory -Force
    $null = New-Item -Path (Split-Path $OtherPath -Parent) -ItemType Directory -Force
    [IO.File]::WriteAllText($PreferredPath, '<configurations><schema version="2.3.16.0" /><configuration type="install" /></configurations>')
    [IO.File]::WriteAllText($OtherPath, '<configurations><schema version="3.2.115.0" /><configuration type="install" /></configurations>')
    $Primary = ConvertFrom-DotNetInstallerConfiguration -Content @'
<configurations>
  <schema version="3.2.115.0" />
  <configuration type="reference"><configfile filename="#TEMPPATH\config\child.xml" /></configuration>
</configurations>
'@ -ConfigurationSource 'PE:CUSTOM/RES_CONFIGURATION'

    $Resolution = InModuleScope DotNetInstaller -Parameters @{
      Primary = $Primary
      Files   = [System.IO.FileInfo[]]@((Get-Item $PreferredPath), (Get-Item $OtherPath))
    } {
      param ($Primary, $Files)
      Resolve-DotNetInstallerConfigurationSet -PrimaryConfiguration $Primary -ReferenceFile $Files
    }

    $Resolution.Configuration.References[0].ResolutionStatus | Should -Be 'Resolved'
    $Resolution.Configuration.References[0].ResolvedPath | Should -Be $PreferredPath
    $Resolution.Configuration.ConfigurationDocuments.Count | Should -Be 2
    $Resolution.Configuration.HasReferenceRisk | Should -BeTrue
    $Resolution.Diagnostics.Id | Should -Contain 'DotNetInstaller.Configuration.ReferenceSchemaMismatch'
    $Resolution.Diagnostics.Id | Should -Not -Contain 'DotNetInstaller.Configuration.ReferenceAmbiguous'
  }

  It 'Resolves mode-specific post-install commands' {
    $Content = @'
<configurations>
  <configuration type="install" complete_command="#CABPATH\bin\Product.exe /first" complete_command_silent="#CABPATH\bin\Product.exe /quiet" />
</configurations>
'@
    $Result = ConvertFrom-DotNetInstallerConfiguration -Content $Content -ArchiveEntry @('bin\Product.exe')

    $Result.Configurations[0].CompleteCommands.Count | Should -Be 3
    $Result.Configurations[0].CompleteCommands[1].Command.ArgumentList | Should -Be @('/quiet')
    $Result.Configurations[0].CompleteCommands[2].Command.ExecutedPayload | Should -Be 'bin\Product.exe'
  }

  It 'Distinguishes outer quiet mode from nested command fallback and reconstructs uninstall commands' {
    $Content = @'
<configurations>
  <configuration type="install">
    <control type="license" id="EULA" accepted="False" />
    <component type="msi" id="runtime" package="Runtime.msi" cmdparameters_basic="/qb"
      uninstall_package="" uninstall_cmdparameters_silent="/qn" supports_uninstall="True">
      <installedcheck type="check_product" id="{11111111-1111-1111-1111-111111111111}" id_type="productcode"
        propertyname="ProductName" propertyvalue="Runtime" comparison="match" defaultvalue="False" />
    </component>
  </configuration>
</configurations>
'@
    $Result = ConvertFrom-DotNetInstallerConfiguration -Content $Content -ArchiveEntry @('Runtime.msi')
    $Component = $Result.Components[0]
    $SilentInstall = $Component.Commands | Where-Object Mode -EQ Silent
    $SilentUninstall = $Component.UninstallCommands | Where-Object Mode -EQ Silent

    $SilentInstall.ModeSource | Should -Be 'Basic'
    $SilentInstall.UsesModeFallback | Should -BeTrue
    $SilentInstall.IsUnattendedRouteProven | Should -BeFalse
    $SilentUninstall.RawCommandLine | Should -Be 'msiexec.exe /x "Runtime.msi" /qn'
    $SilentUninstall.IsUnattendedRouteProven | Should -BeTrue
    $Component.SupportsUninstall | Should -BeTrue
    $Result.Controls[0].Attributes.type | Should -Be 'license'
    $Result.InstalledProductChecks[0].IdType | Should -Be 'productcode'
    $Result.InstalledProductChecks[0].Id | Should -Be '{11111111-1111-1111-1111-111111111111}'
  }

  It 'Selects nested MSI evidence with source-accurate architecture and LCID filters' {
    $Info = [pscustomobject]@{
      NestedInstallerInfos = @(
        [pscustomobject]@{
          ProductCode = 'x86'
          Occurrences = @([pscustomobject]@{
              ConfigurationArchitectureFilter = 'x86'
              ComponentArchitectureFilter     = ''
              ConfigurationLcidFilter         = '1033'
              ComponentLcidFilter             = ''
            })
        },
        [pscustomobject]@{
          ProductCode = 'x64'
          Occurrences = @([pscustomobject]@{
              ConfigurationArchitectureFilter = 'x64'
              ComponentArchitectureFilter     = '!arm64'
              ConfigurationLcidFilter         = '1033'
              ComponentLcidFilter             = ''
            })
        }
      )
    }

    $Selection = Get-DotNetInstallerNestedMsiSelection -Info $Info -Architecture x64 -InstallerLocale en-US

    $Selection.Status | Should -Be 'Selected'
    $Selection.Selected.ProductCode | Should -Be 'x64'
    $Selection.Lcid | Should -Be '1033'
    (Get-DotNetInstallerNestedMsiSelection -Info $Info -Architecture arm64 -InstallerLocale en-US).Status | Should -Be 'NoMatch'
  }

  It 'Rejects mixed positive and negative runtime filters' {
    InModuleScope DotNetInstaller {
      { Test-DotNetInstallerListFilter -Filter 'x64,!x86' -Value x64 } | Should -Throw '*mixes positive and negative*'
    }
  }
}

Describe 'dotNetInstaller historical resource routes' {
  It 'Classifies global and component cabinets with and without the CAB suffix' -ForEach @(
    @{ Names = @('SETUP_1'); Expected = 'GlobalCabinetExtensionless' },
    @{ Names = @('SETUP_1.CAB'); Expected = 'GlobalCabinetNamed' },
    @{ Names = @('SETUP_1', 'SETUP_RUNTIME_1'); Expected = 'PerComponentCabinetsExtensionless' },
    @{ Names = @('SETUP_1.CAB', 'SETUP_RUNTIME_1.CAB'); Expected = 'PerComponentCabinetsNamed' }
  ) {
    InModuleScope DotNetInstaller -Parameters @{ Names = $Names; Expected = $Expected } {
      param ($Names, $Expected)
      $Resources = @($Names | ForEach-Object { [pscustomobject]@{ Name = $_ } })
      $Components = @([pscustomobject]@{ CabinetKey = 'RUNTIME'; Id = 'runtime' })

      (Get-DotNetInstallerCabinetLayout -Resource $Resources -Component $Components).Generation | Should -Be $Expected
    }
  }

  It 'Parses a configuration-only legacy runtime without attempting cabinet extraction' {
    $Path = Resolve-DumplingsTestFixturePath 'Installers\dotNetInstaller\Historical\dotNetInstaller-2007.exe'
    $Sha256 = '4A3B93B494C3EA416C472A8961961699F646848A6B9A1666525D7DFA81736951'
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Path -Sha256 $Sha256)) { Set-ItResult -Skipped -Because 'The historical dotNetInstaller fixture is not cached.'; return }

    $Info = Get-DotNetInstallerInfo -Path $Path

    $Info.FormatGeneration | Should -Be 'ConfigurationOnly'
    $Info.RuntimeCapabilityProfile | Should -Be 'LegacyQuiet'
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.InstallerSwitches.Silent | Should -Be '/q'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/q'
    $Info.UnresolvedFields | Should -Contain 'ProductCode'
  }
}

Describe 'dotNetInstaller official release media' {
  BeforeAll {
    $Script:DotNetInstallerFixtures = @(
      [pscustomobject]@{
        Version = '2.3.16.0'
        Path    = Resolve-DumplingsTestFixturePath 'Installers\dotNetInstaller\OfficialSamples\2.3\Samples_PackagedSetup_Package_Setup.exe'
        Sha256  = '0EFAB431EBD321002C333F9AD320CA7AE79C2032594A1106A4633BD8BB38ADA1'
      },
      [pscustomobject]@{
        Version = '3.2.115.0'
        Path    = Resolve-DumplingsTestFixturePath 'Installers\dotNetInstaller\OfficialSamples\3.2.115\Samples_PackagedSetup_Package_Setup.exe'
        Sha256  = '79A06AC394B5B12DF7777CB25B9B62B9975F569CE3476243ABB8225657D53020'
      }
    )
  }

  It 'Parses the stable per-component resource route from schema <Version>' -ForEach @(
    @{ Version = '2.3.16.0'; Index = 0 },
    @{ Version = '3.2.115.0'; Index = 1 }
  ) {
    $Fixture = $Script:DotNetInstallerFixtures[$Index]
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture.Path -Sha256 $Fixture.Sha256)) { Set-ItResult -Skipped -Because 'The official dotNetInstaller fixture is not cached.'; return }

    $Info = Get-DotNetInstallerInfo -Path $Fixture.Path

    $Info.SchemaVersion | Should -Be $Version
    $Info.RuntimeVersion | Should -Be $Version
    $Info.RuntimeVersionEvidence | Should -Be 'SchemaAndCompiledToken'
    $Info.FormatGeneration | Should -Be 'PerComponentCabinetsNamed'
    $Info.XmlStorageRoute | Should -Be 'OrderedChildren'
    $Info.CabinetSets.Count | Should -Be 2
    $Info.ExecutedPayloads | Should -Contain 'Simple\Simple.msi'
    $Info.ProductCode | Should -Be '{89DD6045-A45B-4ED4-9C06-E93316D52A1D}'
    $Info.NestedInstallerInfos[0].CabinetKey | Should -Be 'SIMPLE'
    $Info.UnresolvedFields | Should -BeNullOrEmpty
  }

  It 'Extracts the configured duplicate-basename payload from its exact path' {
    $Fixture = $Script:DotNetInstallerFixtures[0]
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture.Path -Sha256 $Fixture.Sha256)) { Set-ItResult -Skipped -Because 'The official dotNetInstaller fixture is not cached.'; return }
    $Output = Join-Path $TestDrive 'extract'

    $Files = @(Expand-DotNetInstaller -Path $Fixture.Path -DestinationPath $Output -Name 'Simple\Simple.msi' -CollisionAction Error)

    $Files.Count | Should -Be 1
    $Files[0] | Should -Be (Join-Path $Output 'Simple\Simple.msi')
    (Get-Item $Files[0]).Length | Should -Be 88576
  }

  It 'Uses an explicitly supplied sidecar MSI as the final ARP owner' {
    $Fixture = $Script:DotNetInstallerFixtures[0]
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture.Path -Sha256 $Fixture.Sha256)) { Set-ItResult -Skipped -Because 'The official dotNetInstaller fixture is not cached.'; return }
    $PayloadFolder = Join-Path $TestDrive 'sidecar-source'
    $CompanionMsi = @(Expand-DotNetInstaller -Path $Fixture.Path -DestinationPath $PayloadFolder -Name 'Simple\Simple.msi' -CollisionAction Error)[0]
    $ConfigurationPath = Join-Path $TestDrive 'configuration.xml'
    [IO.File]::WriteAllText($ConfigurationPath, @'
<configurations productversion="1.0">
  <schema version="2.3.16.0" generator="sidecar-test" />
  <configuration type="install" administrator_required="True" processor_architecture_filter="x86">
    <component type="msi" id="sidecar" package="#TEMPPATH\Simple.msi" cmdparameters_silent="/qn" />
  </configuration>
</configurations>
'@)

    $Info = Get-DotNetInstallerInfo -Path $Fixture.Path -ConfigurationPath $ConfigurationPath -CompanionPath $CompanionMsi

    Test-DotNetInstaller -Path $Fixture.Path -ConfigurationPath $ConfigurationPath | Should -BeTrue
    $Info.ProductCode | Should -Be '{89DD6045-A45B-4ED4-9C06-E93316D52A1D}'
    $Info.NestedInstallerInfos.Count | Should -Be 1
    $Info.NestedInstallerInfos[0].SourceKind | Should -Be 'Companion'
    $Info.NestedInstallerInfos[0].SourcePath | Should -Be $CompanionMsi
    $Info.NestedInstallModes | Should -Contain 'silent'
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
  }

  It 'Copies explicitly supplied companion payloads through bounded extraction' {
    $Fixture = $Script:DotNetInstallerFixtures[0]
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture.Path -Sha256 $Fixture.Sha256)) { Set-ItResult -Skipped -Because 'The official dotNetInstaller fixture is not cached.'; return }
    $CompanionPath = Join-Path $TestDrive 'SidecarOnly.bin'
    [IO.File]::WriteAllBytes($CompanionPath, [Text.Encoding]::ASCII.GetBytes('sidecar'))
    $Output = Join-Path $TestDrive 'sidecar-output'

    $Files = @(Expand-DotNetInstaller -Path $Fixture.Path -DestinationPath $Output -Name 'SidecarOnly.bin' -CompanionPath $CompanionPath -CollisionAction Error)

    $Files | Should -Be @(Join-Path $Output 'SidecarOnly.bin')
    [IO.File]::ReadAllText($Files[0]) | Should -Be 'sidecar'
  }

  It 'Promotes a validated resource layout from a marker hint to a confirmed analyzer family' {
    $Fixture = $Script:DotNetInstallerFixtures[0]
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture.Path -Sha256 $Fixture.Sha256)) { Set-ItResult -Skipped -Because 'The official dotNetInstaller fixture is not cached.'; return }

    $Analysis = Get-InstallerAnalysis -Path $Fixture.Path

    $Analysis.DetectedFamilies.Family | Should -Contain 'dotNetInstaller'
    ($Analysis.ParserResults | Where-Object Name -EQ dotNetInstaller).Success | Should -BeTrue
  }

  It 'Parses one current nested MSI once across repeated locale configurations' {
    $Path = Resolve-DumplingsTestFixturePath 'Installers\dotNetInstaller\Wibu-Systems.CodeMeterRuntimeKit\9.10\CodeMeterRuntime.exe'
    $Sha256 = '6361058B5399018DB54FDB5CC15D993F2BC2CDD0F1E366FE1252FD93E236CE7D'
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Path -Sha256 $Sha256)) { Set-ItResult -Skipped -Because 'The CodeMeter Runtime fixture is not cached.'; return }

    $Info = Get-DotNetInstallerInfo -Path $Path

    $Info.RuntimeCapabilityProfile | Should -Be 'RebootControl'
    $Info.RuntimeVersion | Should -Be '3.2.115.0'
    $Info.NestedInstallerInfos.Count | Should -Be 1
    $Info.NestedInstallerInfos[0].ConfigurationIndices | Should -Be @(0, 1, 2, 3, 4)
    $Info.NestedInstallerInfos[0].Occurrences.Count | Should -Be 15
    $Info.ProductCode | Should -Be '{165ECAA0-A92F-4978-99D6-34FBE683180E}'
    $Info.UpgradeCode | Should -Be '{CA3262B1-A5FA-4AC8-A3F0-72873B23C30C}'
    $Info.DisplayVersion | Should -Be '9.10.8166.500'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UnresolvedFields | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Contain 'DotNetInstaller.Installability.SilentRouteUnproven'
  }
}
