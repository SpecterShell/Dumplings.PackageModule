BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Archive.psm1') -Force
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\WinGetInstallerAnalyzer'
  $Script:DeclaredTypeFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'ManifestUpdateDeclaredTypes'
  $ProgressPreference = 'SilentlyContinue'

  function Get-AnalyzerInstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }

  function Get-DeclaredTypeRegressionFixture {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][uri]$Url,
      [Parameter(Mandatory)][string]$Sha256
    )

    Get-DumplingsTestFixture -Directory $Script:DeclaredTypeFixtureDirectory -Name $Name -Uri $Url -Sha256 $Sha256
  }

  function Get-AnalyzerMsixFixtureFromTemplate {
    param(
      [Parameter(Mandatory)]
      [string]$Name
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    if (Test-Path -LiteralPath $FixturePath) { return $FixturePath }

    $SourcePath = Join-Path $Script:FixtureDirectory ([System.IO.Path]::GetFileNameWithoutExtension($Name))
    $null = New-Item -Path $SourcePath -ItemType Directory -Force
    @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Contoso.DependencyTest" Publisher="CN=Contoso" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Dependency Test</DisplayName>
    <PublisherDisplayName>Contoso</PublisherDisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
    <PackageDependency Name="Microsoft.WindowsAppRuntime.1.7" MinVersion="7000.0.0.0" Publisher="CN=Microsoft Corporation" />
    <PackageDependency Name="Contoso.UnknownFramework" MinVersion="1.0.0.0" Publisher="CN=Contoso" />
  </Dependencies>
</Package>
'@ | Set-Content -LiteralPath (Join-Path $SourcePath 'AppxManifest.xml') -Encoding UTF8
    [System.IO.File]::WriteAllBytes((Join-Path $SourcePath 'AppxSignature.p7x'), [byte[]](1, 2, 3, 4))
    Compress-Archive -Path (Join-Path $SourcePath '*') -DestinationPath $FixturePath -Force
    return $FixturePath
  }

  function Get-AnalyzerInstall4jFixtureFromTemplate {
    param(
      [Parameter(Mandatory)]
      [string]$Name
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    if (Test-Path -LiteralPath $FixturePath) { return $FixturePath }

    @'
MZ
install4j i4jruntime.jar.pack;i4jparams.conf;user.jar.pack allinstdirs1234-5678-9012-3456
<?xml version="1.0" encoding="UTF-8"?>
<config install4jVersion="9.0.7" install4jBuild="9184" type="windows" archive="false" bitness="64">
  <general applicationName="Analyzer install4j App" applicationVersion="1.2.3" mediaSetId="1" applicationId="1234-5678-9012-3456" mediaName="Analyzer" jreVersion="17" minJavaVersion="17" publisherName="Contoso Ltd." publisherURL="https://contoso.example" lzmaCompression="true" installerType="1" uninstallerFilename="uninstall" uninstallerDirectory="." defaultInstallationDirectory="{appdata}{/}Analyzer" privilegedInstallerRequest="true" />
  <screens>
    <screen id="1">
      <actions>
        <action id="2">
          <java version="11.0.15" class="java.beans.XMLDecoder">
            <object class="com.install4j.runtime.beans.actions.desktop.RegisterAddRemoveAction">
              <void property="itemName">
                <string>Analyzer install4j App 1.2.3</string>
              </void>
            </object>
          </java>
          <actionLists />
        </action>
      </actions>
    </screen>
  </screens>
</config>
'@ | Set-Content -LiteralPath $FixturePath -Encoding UTF8

    return $FixturePath
  }
}

Describe 'Installer manifest behavior defaults' {
  It 'Should mirror documented Advanced Installer modes and return codes' {
    InModuleScope WinGetInstallerAnalyzer {
      $Defaults = Get-WinGetInstallerExeFamilyDefault -Family 'Advanced Installer'

      $Defaults.InstallModes | Should -Be @('interactive', 'silent', 'silentWithProgress')
      $Defaults.ExpectedReturnCodes.Count | Should -Be 20
      ($Defaults.ExpectedReturnCodes | Where-Object InstallerReturnCode -EQ 3010).ReturnResponse | Should -Be 'rebootRequiredToFinish'
    }
  }

  It 'Should limit generic EXE families without progress mode support' {
    InModuleScope WinGetInstallerAnalyzer {
      (Get-WinGetInstallerExeFamilyDefault -Family 'Squirrel').InstallModes | Should -Be @('interactive', 'silent')
    }
  }

  It 'Should mirror the documented InstallShield Advanced UI snippet' {
    InModuleScope WinGetInstallerAnalyzer {
      $Defaults = Get-WinGetInstallerExeFamilyDefault -Family 'InstallShield Advanced UI'

      $Defaults.InstallerSwitches.Silent | Should -Be '/silent'
      $Defaults.InstallerSwitches.SilentWithProgress | Should -Be '/passive'
      $Defaults.ExpectedReturnCodes.Count | Should -Be 19
      ($Defaults.ExpectedReturnCodes | Where-Object InstallerReturnCode -EQ 0x80040711).ReturnResponse | Should -Be 'installInProgress'
    }
  }

  It 'Should not invent scope where the documented generic-family snippet omits it' {
    InModuleScope WinGetInstallerAnalyzer {
      foreach ($Family in @('Setup Factory', 'InstallAnywhere', 'InstallMate', 'QSetup', 'Paquet Builder')) {
        (Get-WinGetInstallerExeFamilyDefault -Family $Family).PSObject.Properties.Name | Should -Not -Contain 'Scope'
      }
    }
  }

  It 'Should mirror documented Wise and Qt IFW installer-level fields' {
    InModuleScope WinGetInstallerAnalyzer {
      $Wise = Get-WinGetInstallerExeFamilyDefault -Family 'Wise'
      $Qt = Get-WinGetInstallerExeFamilyDefault -Family 'Qt Installer Framework'

      $Wise.Scope | Should -Be 'machine'
      $Wise.InstallerSwitches.InstallLocation | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
      $Qt.UpgradeBehavior | Should -Be 'uninstallPrevious'
    }
  }
}

Describe 'WinGet installer analyzer content detection' {
  It 'Should classify MSI by CFB root CLSID even when the extension is wrong' {
    $Msi = Get-AnalyzerInstallerFixture -Name 'draw.io-30.2.6.msi' -Url 'https://github.com/jgraph/drawio-desktop/releases/download/v30.2.6/draw.io-30.2.6.msi'
    $RenamedMsi = Join-Path $Script:FixtureDirectory 'draw.io-30.2.6.bin'
    Copy-Item -LiteralPath $Msi -Destination $RenamedMsi -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $RenamedMsi

    $Analysis.DetectedFileType.Type | Should -Be 'MSI'
    $Analysis.DetectedFileType.Evidence.ClassId | Should -Be '{000C1084-0000-0000-C000-000000000046}'
    $Analysis.ParserResults[0].Success | Should -BeTrue
  }

  It 'Should classify MSP by CFB root CLSID rather than extension' {
    $Msp = Get-AnalyzerInstallerFixture -Name 'Patch-1.33.107.0-release.x64.msp' -Url 'https://download.macrobond.com/installation/mainapp/1.23.0.3853-release/Patch-1.33.107.0-release.x64.msp'
    $MspLike = Join-Path $Script:FixtureDirectory 'Patch-1.33.107.0-release.x64.bin'
    Copy-Item -LiteralPath $Msp -Destination $MspLike -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $MspLike

    $Analysis.DetectedFileType.Type | Should -Be 'MSP'
    $Analysis.DetectedFileType.Evidence.Format | Should -Be 'Windows Installer Patch'
    $Analysis.ParserResults[0].Result.InstallerType | Should -Be 'msp'
  }

  It 'Should reject unsigned MSIX/AppX-family packages' {
    $UnsignedMsix = Get-AnalyzerInstallerFixture -Name 'XmlNotepadPackage_2.9.0.17_AnyCPU.msixbundle' -Url 'https://github.com/microsoft/XmlNotepad/releases/download/2.9.0.17/XmlNotepadPackage_2.9.0.17_AnyCPU.msixbundle'

    $Analysis = Get-WinGetInstallerAnalysis -Path $UnsignedMsix

    $Analysis.DetectedFileType.Type | Should -Be 'MSIXAppX'
    $Analysis.ParserResults[0].Result.InstallerType | Should -Be 'msix'
    $Analysis.ParserResults[0].Result.PackageKind | Should -Be 'Bundle'
    $Analysis.ParserResults[0].Result.SignatureEvidence.Status | Should -Be 'NotSigned'
    $Analysis.ParserResults[0].Result.SignatureEvidence.IsSigned | Should -BeFalse
    $Analysis.ParserResults[0].Result.SignatureEvidence.IsTrusted | Should -BeFalse
    $Analysis.ParserResults[0].Result.Rejected | Should -BeTrue
    $Analysis.BlockingIssues | Should -Contain 'Reject: MSIX/AppX-family packages must contain a signature.'
  }

  It 'Should reject signed MSIX/AppX-family packages whose signature is not trusted by the system' {
    $UntrustedMsix = Get-AnalyzerInstallerFixture -Name 'Lamina_11.28000.16.0_x64.msix' -Url 'https://github.com/Chill-Astro/Lamina-Calculator/releases/download/v11.28000.16.0/Lamina_11.28000.16.0_x64.msix'

    $Analysis = Get-WinGetInstallerAnalysis -Path $UntrustedMsix

    $Analysis.DetectedFileType.Type | Should -Be 'MSIXAppX'
    $Analysis.ParserResults[0].Result.InstallerType | Should -Be 'msix'
    $Analysis.ParserResults[0].Result.PackageKind | Should -Be 'Package'
    $Analysis.ParserResults[0].Result.SignatureEvidence.IsSigned | Should -BeTrue
    $Analysis.ParserResults[0].Result.SignatureEvidence.IsTrusted | Should -BeFalse
    $Analysis.ParserResults[0].Result.SignatureSha256 | Should -Not -BeNullOrEmpty
    $Analysis.ParserResults[0].Result.Rejected | Should -BeTrue
    $Analysis.BlockingIssues | Should -Contain 'Reject: MSIX/AppX-family package signature is not valid and trusted by this system.'
  }

  It 'Should warn about unknown MSIX/AppX package dependencies and omit them from suggested manifest dependencies' {
    $Msix = Get-AnalyzerMsixFixtureFromTemplate -Name 'DependencyTest.msix'

    $Analysis = Get-WinGetInstallerAnalysis -Path $Msix
    $Result = $Analysis.ParserResults[0].Result

    $Analysis.DetectedFileType.Type | Should -Be 'MSIXAppX'
    $Result.Dependencies.PackageDependencies.PackageIdentifier | Should -Contain 'Microsoft.WindowsAppRuntime.1.7'
    $Result.Dependencies.PackageDependencies.PackageIdentifier | Should -Not -Contain 'Contoso.UnknownFramework'
    $Result.UnknownPackageDependencies.PackageIdentifier | Should -Contain 'Contoso.UnknownFramework'
    $Result.Warnings[0] | Should -BeLike '*Contoso.UnknownFramework*not included*'
    $Analysis.SuggestedNextSteps | Should -Contain $Result.Warnings[0]
  }

  It 'Should expose structured install4j parser evidence for install4j launchers' {
    $Installer = Get-AnalyzerInstall4jFixtureFromTemplate -Name 'AnalyzerInstall4j-v2.exe'

    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object -FilterScript { $_.Name -eq 'install4j' } | Select-Object -First 1

    $Result.Success | Should -BeTrue
    $Result.Result.ProductCode | Should -Be '1234-5678-9012-3456'
    $Result.Result.ProductVersion | Should -Be '1.2.3'
    $Result.Result.Publisher | Should -Be 'Contoso Ltd.'
    $Result.Result.Metadata.EmbeddedFiles | Should -Contain 'i4jparams.conf'
  }

  It 'Should expose the configured nested launcher for WinRAR GUI SFX installers' {
    $Installer = Get-AnalyzerInstallerFixture -Name 'Lakes_SCREENView_4.0.1.exe' -Url 'https://www.weblakes.com/products/screen/update/Lakes_Environmental_SCREEN_View_V.4.0.1_Install.exe'

    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object -FilterScript { $_.Name -eq 'WinRAR GUI SFX' } | Select-Object -First 1

    $Result.Success | Should -BeTrue
    $Result.Result.ExecutedPayloads | Should -Contain 'setup.exe'
    $Result.Result.Metadata.Commands[0].Command.ArgumentList | Should -Contain '/w'
  }

  It 'Should expose script and MSI payload evidence for IExpress installers' {
    $Installer = Get-AnalyzerInstallerFixture -Name 'NM34_x64.exe' -Url 'https://download.microsoft.com/download/7/1/0/7105C7FF-768E-4472-AFD5-F29108D1E383/NM34_x64.exe'

    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object -FilterScript { $_.Name -eq 'IExpress' } | Select-Object -First 1

    $Result.Success | Should -BeTrue
    $Result.Result.ExecutedPayloads | Should -Contain 'nmsetup.vbs'
    $Result.Result.NestedInstallerFiles | Should -Contain 'netmon.msi'
  }

  It 'Should use the documented Actual Installer dual-scope switch defaults' {
    $Module = Get-Module WinGetInstallerAnalyzer
    $Defaults = & $Module { Get-WinGetInstallerExeFamilyDefault -Family 'Actual Installer' }

    $Defaults.InstallerSwitches.Silent | Should -Be '/S /L'
    $Defaults.InstallerSwitches.InstallLocation | Should -Be '/D "<INSTALLPATH>"'
    $Defaults.ScopeSwitches.User | Should -Be '/CU'
    $Defaults.ScopeSwitches.Machine | Should -Be '/RUNAS /ALL'
    $Defaults.Notes | Should -Contain 'Actual Installer can use /CU for current-user scope and /RUNAS /ALL for machine scope.'
  }

  It 'Should route Paquet Builder markers to its family defaults' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'PaquetBuilder-marker.exe'
    [System.IO.File]::WriteAllText($FixturePath, 'MZ Paquet Builder Setup G.D.G. Software installpackbuilder.com')
    $Module = Get-Module WinGetInstallerAnalyzer
    $Candidate = & $Module {
      param($FixturePath)
      Get-WinGetInstallerGenericExeFamilyCandidate -File (Get-Item -LiteralPath $FixturePath) -Budget 1048576 |
        Where-Object Family -EQ 'Paquet Builder' |
        Select-Object -First 1
    } $FixturePath

    $Candidate.Family | Should -Be 'Paquet Builder'
    $Candidate.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'Scope'
    $Candidate.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/s'
  }

  It 'Should route CreateInstall markers to its family defaults' {
    $FixturePath = Join-Path $Script:FixtureDirectory 'CreateInstall-marker.exe'
    [System.IO.File]::WriteAllText($FixturePath, 'MZ CreateInstall Novostrim .ciq')
    $Module = Get-Module WinGetInstallerAnalyzer
    $Candidate = & $Module {
      param($FixturePath)
      Get-WinGetInstallerGenericExeFamilyCandidate -File (Get-Item -LiteralPath $FixturePath) -Budget 1048576 |
        Where-Object Family -EQ 'CreateInstall' |
        Select-Object -First 1
    } $FixturePath

    $Candidate.Family | Should -Be 'CreateInstall'
    $Candidate.SuggestedManifestFields.Scope | Should -Be 'machine'
    $Candidate.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '-silent'
  }

  It 'Should keep CreateInstall text inside Codeg as a rejected route after NSIS succeeds' {
    $Installer = Get-DeclaredTypeRegressionFixture -Name 'codeg_0.21.5_x64-setup.exe' -Url 'https://github.com/xintaofei/codeg/releases/download/v0.21.5/codeg_0.21.5_x64-setup.exe' -Sha256 '4774C23369A92D788C31D1CB80093E45973428C9329221308A67D8CDBBB07A74'

    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer

    $Analysis.DetectedFamilies.Family | Should -Contain 'NSIS/Nullsoft'
    $Analysis.FamilyCandidates.Family | Should -Contain 'NSIS/Nullsoft'
    $Analysis.FamilyCandidates.Family | Should -Not -Contain 'CreateInstall'
    $Analysis.RoutingHints.Family | Should -Contain 'CreateInstall'
    ($Analysis.RejectedCandidates | Where-Object Family -EQ 'CreateInstall').ParserName | Should -Be 'CreateInstall'
  }

  It 'Should keep CreateInstall text inside PixPin as a rejected route after Inno succeeds' {
    $Installer = Get-DeclaredTypeRegressionFixture -Name 'PixPin_win_3.4.2.1.exe' -Url 'https://download.pixpinapp.com/PixPin_win_3.4.2.1.exe' -Sha256 '02F23A4A71EC8F8FD60F071FA6157B83A0478BB2B478E2A00598C1CF752C9287'

    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer

    $Analysis.DetectedFamilies.Family | Should -Contain 'Inno Setup'
    $Analysis.FamilyCandidates.Family | Should -Contain 'Inno Setup'
    $Analysis.FamilyCandidates.Family | Should -Not -Contain 'CreateInstall'
    $Analysis.RoutingHints.Family | Should -Contain 'CreateInstall'
    ($Analysis.RejectedCandidates | Where-Object Family -EQ 'CreateInstall').ValidationStatus | Should -Be 'RejectedByParser'
  }

  It 'Should not promote common embedded marker strings when their parser rejects the file' -ForEach @(
    @{ Family = 'CreateInstall'; Markers = 'CreateInstall Novostrim .ciq' }
    @{ Family = 'Squirrel'; Markers = 'SquirrelSetup Update.exe RELEASES package.nupkg' }
  ) {
    $FixturePath = Join-Path $TestDrive "$Family-marker-host.exe"
    Copy-Item -LiteralPath (Get-Process -Id $PID).Path -Destination $FixturePath
    $Stream = [IO.File]::Open($FixturePath, 'Append', 'Write', 'Read')
    try {
      $Bytes = [Text.Encoding]::ASCII.GetBytes("`0$Markers`0")
      $Stream.Write($Bytes)
    } finally {
      $Stream.Dispose()
    }

    $Analysis = Get-WinGetInstallerAnalysis -Path $FixturePath

    $Analysis.DetectedFamilies.Family | Should -Not -Contain $Family
    $Analysis.FamilyCandidates.Family | Should -Not -Contain $Family
    $Analysis.RoutingHints.Family | Should -Contain $Family
    $Analysis.RejectedCandidates.Family | Should -Contain $Family
  }

  It 'Should prefer a structured generic EXE parser over archive-wrapper heuristics' {
    InModuleScope WinGetInstallerAnalyzer {
      Mock Get-SetupFactoryInfo { throw 'not Setup Factory' }
      Mock Get-InstallAnywhereInfo { throw 'not InstallAnywhere' }
      Mock Get-ActualInstallerInfo { throw 'not Actual Installer' }
      Mock Get-InstallBuilderInfo { throw 'not InstallBuilder' }
      Mock Get-InstallForgeInfo { throw 'not InstallForge' }
      Mock Get-InstallAwareInfo { throw 'not InstallAware' }
      Mock Get-PaquetBuilderInfo { throw 'not Paquet Builder' }
      Mock Get-QSetupInfo {
        [pscustomobject]@{
          DisplayName = 'Analyzer QSetup Product'; DisplayVersion = '1.2.3'; Publisher = 'Contoso'
          ProductCode = 'Analyzer QSetup Product'; Scope = 'machine'; SupportedScopes = @('machine')
          Protocols = @(); FileExtensions = @('example'); RegistryAssociationInfo = $null
          ExtractedFiles = @('Setup.txt'); CanExpand = $true; Warnings = @()
        }
      }
      Mock Get-DeployMasterInfo { throw 'not DeployMaster' }
      Mock Get-CreateInstallInfo { throw 'not CreateInstall' }
      Mock Get-InstallMateInfo { throw 'not InstallMate' }
      Mock Get-SevenZipSfxInfo { throw 'archive wrapper heuristic must not run' }

      $Results = @(Invoke-WinGetInstallerExeParser -InstallerPath 'synthetic-qsetup.exe' -ExtractEmbeddedMsi:$false)
      $QSetup = $Results | Where-Object { $_.Name -eq 'QSetup' -and $_.Success } | Select-Object -First 1

      $QSetup.Result.ProductName | Should -Be 'Analyzer QSetup Product'
      $QSetup.Result.ProductVersion | Should -Be '1.2.3'
      $QSetup.Result.SuggestedManifestFields.Scope | Should -Be 'machine'
      $QSetup.Result.SuggestedManifestFields.InstallModes | Should -Be @('interactive', 'silent', 'silentWithProgress')
      Should -Invoke -CommandName Get-SevenZipSfxInfo -Times 0 -Exactly
    }
  }

  It 'Should remove silent switches from GUI-only Qt IFW analyzer evidence' {
    $Installer = Get-AnalyzerInstallerFixture -Name 'qtlinguistinstaller-5.12.2.exe' -Url 'https://download.qt.io/linguist_releases/qtlinguistinstaller-5.12.2.exe'
    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object Name -EQ 'Qt Installer Framework' | Select-Object -First 1

    $Result.Success | Should -BeTrue
    $Result.Result.InterfaceVariant | Should -Be 'GUI'
    $Result.Result.SupportsSilentInstallation | Should -BeFalse
    $Result.Result.SupportsExistingInstallationOverride | Should -BeFalse
    $Result.Result.RecommendedUpgradeBehavior | Should -Be 'uninstallPrevious'
    $Result.Result.SuggestedManifestFields.InstallModes | Should -Be @('interactive')
    $Result.Result.SuggestedManifestFields.InstallerSwitches.Count | Should -Be 0
    $Result.Result.SuggestedManifestFields.UpgradeBehavior | Should -Be 'uninstallPrevious'
  }
}
