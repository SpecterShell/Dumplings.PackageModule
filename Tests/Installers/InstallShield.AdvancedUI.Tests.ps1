. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldTestSetup.ps1')

Describe 'InstallShield Advanced UI and prerequisites' -Tag Unit {
It 'Should parse Advanced UI SuiteId and its exact nested package catalog' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SketchUpViewer-2022-0-316-108.exe')
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent SketchUp Viewer Advanced UI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.Variant | Should -Be 'Advanced UI'
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2021'
      $Info.InstallShieldRelease.Confidence | Should -Be 'ExactSuiteNamespace'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Suite/AdvancedUI'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Script/aLuZ'
      $Info.ProductCode | Should -Be '{29A129E0-9D13-44AF-A89A-E4CEFB491AF4}'
      $Info.DisplayName | Should -Be 'SketchUp Viewer'
      $Info.DisplayVersion | Should -Be '22.0.316'
      $Info.Publisher | Should -Be 'Trimble, Inc.'
      $Info.Scope | Should -Be 'machine'
      $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\SketchUp\SketchUp Viewer 2022'
      $Info.SuitePackages.Count | Should -Be 2
      $Info.AdvancedUiInfo.Selections.Name | Should -Contain 'SketchUpBase'
      $Info.AdvancedUiInfo.Modes.Name | Should -Be @('Install', 'Maintenance')
      $Info.AdvancedUiInfo.Actions.Type | Should -Contain 'CallInstallScript'
      $Info.AdvancedUiInfo.InstallScriptEntryPoints | Should -Be @('CheckLanguage', 'SetLanguages')
      $Info.InstallScriptInfo.InstallEntryPoints | Should -Be @('CheckLanguage', 'SetLanguages')
      $Info.InstallScriptInfo.SilentSupport | Should -Be 'NotApplicable'
      $Info.InstallScriptInfo.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      $Info.AdvancedUiInfo.Events.Event | Should -Contain 'OnEnd'
      $Info.AdvancedUiInfo.AbortConditions.Condition.Children.Type | Should -Contain 'Any'
      $Info.AdvancedUiInfo.PackageArchitectures | Should -Be @('x64')

      $MsiPackage = $Info.SuitePackages | Where-Object Type -EQ 'Msi'
      $MsiPackage.Files.RelativePath | Should -Be '{3B09BEBD-C840-4818-8020-79198814AD80}\SketchUpViewer.msi'
      $MsiPackage.Operations.Target | Should -Contain 'SketchUpViewer.msi'
      $MsiPackage.HidesNestedArp | Should -BeTrue
      $MsiPackage.TransactionMode | Should -Be 'Disabled'
      $MsiPackage.UpgradeType | Should -Be 'Auto'
      ($MsiPackage.Operations | Where-Object Name -EQ 'Install').ExitBehavior | Should -Be 'DetectIgnore'
      $ExeInstallOperation = ($Info.SuitePackages | Where-Object Type -EQ 'Exe').Operations | Where-Object Name -EQ 'Install'
      $ExeInstallOperation.RebootRequest | Should -Be 'DetectReboot'
      $ExeInstallOperation.RebootCodes | Should -Be @(1641, 3010)
      ($Info.SuitePackages | Where-Object Type -EQ 'Exe').Files.SourceUrl | Should -Match '^http://download\.visualstudio\.microsoft\.com/'
      $Info.Warnings | Should -Not -Contain 'Setup.ini did not identify the MSI; the only extracted MSI is used as a bounded fallback.'

      $NestedPackages = Get-InstallShieldAdvancedUiNestedPackageInfo -Info $Info.AdvancedUiInfo -Architecture x64 -OSVersion 10.0 -BuildNumber 19045 -ProductType Workstation
      $NestedMsi = $NestedPackages | Where-Object PackageType -EQ 'Msi'
      $NestedMsi.Success | Should -BeTrue
      $NestedMsi.Parser | Should -Be 'Windows Installer'
      $NestedMsi.Info.ProductCode | Should -Be '{9FDE1EAA-1ACA-28CD-8077-1E3C45E96033}'
      $NestedExe = $NestedPackages | Where-Object PackageType -EQ 'Exe'
      $NestedExe.SourcePath | Should -Exist
      $NestedExe.SourceUrl | Should -Match '^http://download\.visualstudio\.microsoft\.com/'
      if (Get-Command Get-WinGetInstallerAnalysis -ErrorAction SilentlyContinue) {
        $NestedExe.Success | Should -BeTrue
        $NestedExe.Parser | Should -Be 'WinGet installer analyzer'
      } else {
        $NestedExe.Success | Should -BeFalse
        $NestedExe.Warnings | Should -Match 'Get-WinGetInstallerAnalysis is not loaded'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should parse an official InstallShield prerequisite definition without executing its payload' {
    $PrerequisitePath = Join-Path $Script:FixtureDirectory 'synthetic-dotnet-desktop.prq'
    @'
<SetupPrereq>
  <conditions><condition Type="4" Comparison="2" Path="[ProgramFiles64Folder]\dotnet\shared\Microsoft.WindowsDesktop.App\10.0.5" FileName="PresentationFramework.dll" ReturnValue="" Bits="2" /></conditions>
  <operatingsystemconditions><operatingsystemcondition MajorVersion="10" MinorVersion="0" PlatformId="2" Bits="4" /></operatingsystemconditions>
  <files><file LocalFile="&lt;ISProductFolder&gt;\SetupPrerequisites\windowsdesktop-runtime.exe" URL="https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/10.0.5/windowsdesktop-runtime-10.0.5-win-x64.exe" CheckSum="4416E90423F2A264AF51A2377514138E" FileSize="0,60082160" /></files>
  <execute file="windowsdesktop-runtime.exe" cmdline="/q /norestart" cmdlinesilent="/q /norestart" returncodetoreboot="3010,invalid,1641" />
  <properties Id="{86626E11-C623-42F5-9D63-4EF672544EA9}" Description="Microsoft .NET Desktop Runtime 10.0.5 x64" AltPrqURL="https://example.invalid/runtime.prq" />
  <behavior Reboot="4" />
</SetupPrereq>
'@ | Set-Content -LiteralPath $PrerequisitePath -Encoding utf8
    try {
      $Info = Get-InstallShieldPrerequisiteInfo -Path $PrerequisitePath
      $Info.Id | Should -Be '{86626E11-C623-42F5-9D63-4EF672544EA9}'
      $Info.Files[0].Size | Should -Be 60082160
      $Info.SilentCommandLine | Should -Be '/q /norestart'
      $Info.ReturnCodesToReboot | Should -Be @(3010, 1641)
      $Info.InvalidReturnCodesToReboot | Should -Be 'invalid'
      $Info.DetectionConditions[0].Attributes.FileName | Should -Be 'PresentationFramework.dll'
      $Info.DetectionConditions[0].PredicateKind | Should -Be 'File'
      $Info.DetectionConditions[0].Comparison | Should -Be 'DoesNotExist'
      $Info.DetectionConditions[0].EvidenceKey | Should -Be 'File:[ProgramFiles64Folder]\dotnet\shared\Microsoft.WindowsDesktop.App\10.0.5\PresentationFramework.dll'
      $Info.ShouldInstallState | Should -Be 'Unknown'
      $Info.LimitedUserCompatible | Should -BeFalse
      $Info.RequiresAdministrativePrivileges | Should -BeTrue
      $Info.HasSilentCommandLine | Should -BeTrue

      $TargetInfo = Get-InstallShieldPrerequisiteInfo -Path $PrerequisitePath -ConditionEvidence @{
        'File:[ProgramFiles64Folder]\dotnet\shared\Microsoft.WindowsDesktop.App\10.0.5\PresentationFramework.dll' = $false
      } -Architecture x64 -OSVersion 10.0
      $TargetInfo.DetectionConditionAnalyses[0].State | Should -Be 'True'
      $TargetInfo.OperatingSystemConditionAnalyses[0].State | Should -Be 'True'
      $TargetInfo.ShouldInstallState | Should -Be 'True'
    } finally {
      Remove-Item -LiteralPath $PrerequisitePath -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should distinguish limited-user-compatible prerequisite definitions' {
    $PrerequisitePath = Join-Path $TestDrive 'limited-user.prq'
    @'
<SetupPrereq>
  <execute file="dependency.exe" cmdlinesilent="/quiet" />
  <properties Id="{11111111-1111-1111-1111-111111111111}" Description="Limited-user dependency" />
  <behavior Lua="1" Reboot="2" />
</SetupPrereq>
'@ | Set-Content -LiteralPath $PrerequisitePath -Encoding utf8

    $Info = Get-InstallShieldPrerequisiteInfo -Path $PrerequisitePath

    $Info.LimitedUserCompatible | Should -BeTrue
    $Info.RequiresAdministrativePrivileges | Should -BeFalse
    $Info.HasSilentCommandLine | Should -BeTrue
  }

It 'Should evaluate typed InstallShield prerequisite comparisons only from supplied evidence' {
    [xml]$Xml = '<conditions><condition Type="32" Comparison="2" Path="HKEY_LOCAL_MACHINE\Software\Vendor\Runtime" FileName="Version" ReturnValue="2.0.0" Bits="2" /></conditions>'
    $Condition = ConvertFrom-InstallShieldPrerequisiteCondition -Node $Xml.DocumentElement.FirstChild

    $Condition.PredicateKind | Should -Be 'RegistryVersion'
    $Condition.Comparison | Should -Be 'LessThan'
    $Condition.RegistryView | Should -Be 'Registry64'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition).State | Should -Be 'Unknown'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition -Evidence @{ $Condition.EvidenceKey = @{ Exists = $true; Version = '1.5.0' } }).State | Should -Be 'True'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition -Evidence @{ $Condition.EvidenceKey = @{ Exists = $true; Version = '2.1.0' } }).State | Should -Be 'False'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition -Evidence @{ $Condition.EvidenceKey = $false }).State | Should -Be 'False'
  }

It 'Should read ordered setup prerequisite references from Setup.ini' {
    InModuleScope InstallShield {
      $Configuration = ConvertFrom-Ini -Content @'
[ISSetupPrerequisites]
PreReq10=Last.prq
PreReq2=Second.prq
PreReq0=First.prq
'@ -DuplicateKeyAction Last

      $References = @(Get-InstallShieldSetupPrerequisiteReference -Configuration $Configuration)

      $References.Name | Should -Be @('First.prq', 'Second.prq', 'Last.prq')
      $References.Order | Should -Be @(0, 2, 10)
      $References.ReferenceSource | Should -Be @(
        'Setup.ini [ISSetupPrerequisites]',
        'Setup.ini [ISSetupPrerequisites]',
        'Setup.ini [ISSetupPrerequisites]'
      )
    }
  }

It 'Should require elevation only for direct launcher or selected prerequisite evidence' {
    InModuleScope InstallShield {
      $AdminDefinition = [pscustomobject]@{
        Path                             = 'C:\Extracted\Admin.prq'
        Description                      = 'Administrative dependency'
        RequiresAdministrativePrivileges = $true
        SilentCommandLine                = '/quiet'
      }
      $SelectedEvidence = [pscustomobject]@{
        Reference   = [pscustomobject]@{ Name = 'Admin.prq' }
        Definition  = $AdminDefinition
        MatchMethod = 'ExactIdentityOrName'
      }
      $UnreferencedEvidence = [pscustomobject]@{
        Reference   = $null
        Definition  = $AdminDefinition
        MatchMethod = 'UnreferencedDefinition'
      }

      (Get-InstallShieldElevationInfo -RequestedExecutionLevel asInvoker -PrerequisiteEvidence $SelectedEvidence).ElevationRequirement | Should -Be 'elevationRequired'
      (Get-InstallShieldElevationInfo -RequestedExecutionLevel requireAdministrator).Confidence | Should -Be 'DirectPEManifest'
      (Get-InstallShieldElevationInfo -RequestedExecutionLevel asInvoker -PrerequisiteEvidence $UnreferencedEvidence).ElevationRequirement | Should -BeNullOrEmpty
    }
  }

It 'Should keep Advanced UI transactions separate from project packages' {
    $SetupXmlPath = Join-Path $Script:FixtureDirectory 'synthetic-suite-transaction.xml'
    @'
<Setup SuiteId="{11111111-1111-1111-1111-111111111111}" xmlns="installshield/2026/bootstrap">
  <ARPInfo><DisplayName>Example Suite</DisplayName><Version>1.0</Version><Publisher>Example</Publisher></ARPInfo>
  <Parcels>
    <Transaction Id="Transaction1"><ParcelRef Id="Package1" /></Transaction>
    <IsmMsi Platform="x64"><UIProperties><Id>Package1</Id><DisplayName>Example MSI Project</DisplayName></UIProperties><Operation Name="Install" Target="setup.exe"><Silent>/s /v/qn</Silent></Operation></IsmMsi>
  </Parcels>
</Setup>
'@ | Set-Content -LiteralPath $SetupXmlPath -Encoding utf8
    try {
      $Info = Get-InstallShieldAdvancedUiInfo -Path $SetupXmlPath
      $Info.Packages.Count | Should -Be 1
      $Info.Packages[0].Type | Should -Be 'IsmMsi'
      $Info.Packages[0].PackageFamily | Should -Be 'InstallShield Basic MSI Project'
      $Info.Transactions.Count | Should -Be 1
      $Info.Transactions[0].ParcelIds | Should -Be @('Package1')
      $Info.CatalogOrder.Kind | Should -Be @('Transaction', 'Package')
    } finally {
      Remove-Item -LiteralPath $SetupXmlPath -Force -ErrorAction SilentlyContinue
    }
  }

It 'routes the archived InstallShield 5 Professional setup through PackageForTheWeb and old INS' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '5\ArchivedMedia\IS5pro.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 5 Professional fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 5'
      $Info.InstallShieldProjectType | Should -Be 'InstallScript'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Wrapper/PackageForTheWeb'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Cabinet5/LegacyDescriptor'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Script/INS-Old'
      $Info.InstallShieldCabinetSupport.CatalogEntryCount | Should -Be 451
      $Info.InstallShieldCabinetSupport.MediaVersions.StructuralProfile | Should -Be 'LegacyDescriptorWithoutDigest'
      $Info.InstallScriptInfo.ParserVersionInfo.HeaderKind | Should -Be 'INS-Old'
      $Info.InstallScriptInfo.ParserVersionInfo.InstructionCount | Should -BeGreaterThan 4000
      $Info.InstallScriptInfo.ParserVersionInfo.EmulationTruncated | Should -BeFalse
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should parse early Advanced UI point-release namespaces' {
    $SetupXmlPath = Join-Path $Script:FixtureDirectory 'synthetic-suite-2012.2.xml'
    @'
<Setup SuiteId="{D6E404DB-1F4D-4C22-9417-D5785DDCB365}" xmlns="installshield/2012.2/bootstrap">
  <ARPInfo><DisplayName>InstallShield 2012 Spring</DisplayName><Version>19.00.0000</Version><Publisher>Flexera Software LLC</Publisher></ARPInfo>
  <Mode><Install><When><RegistryValue Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D6E404DB-1F4D-4C22-9417-D5785DDCB365}" /></When></Install></Mode>
  <Parcels>
    <Msi ProductCode="{44BA1E0A-99AC-439F-9D97-71F5B92E7E98}" ProductVersion="19.00.0000" Platform="AMD64">
      <UIProperties><Id>Product</Id><DisplayName>InstallShield 2012 Spring MSI</DisplayName></UIProperties>
      <Package><Folder><File Name="payload\InstallShield2012Spring.msi" /></Folder></Package>
      <Operation Name="Install" Target="InstallShield2012Spring.msi"><Silent>ARPSYSTEMCOMPONENT=1 REBOOT=ReallySuppress</Silent></Operation>
    </Msi>
  </Parcels>
</Setup>
'@ | Set-Content -LiteralPath $SetupXmlPath -Encoding utf8
    try {
      $Info = Get-InstallShieldAdvancedUiInfo -Path $SetupXmlPath

      $Info.ReleaseVersion | Should -Be '2012.2'
      $Info.ReleaseYear | Should -Be 2012
      $Info.ProductCode | Should -Be '{D6E404DB-1F4D-4C22-9417-D5785DDCB365}'
      $Info.Scope | Should -Be 'machine'
      $Info.Packages.Count | Should -Be 1
      $Info.Packages[0].Architecture | Should -Be 'x64'
      $Info.Packages[0].Files.RelativePath | Should -Be 'payload\InstallShield2012Spring.msi'
      $Info.Packages[0].HidesNestedArp | Should -BeTrue
    } finally {
      Remove-Item -LiteralPath $SetupXmlPath -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should route the archived 2012 Spring builder through its suite catalog' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '2012Spring\ArchivedMedia\InstallShield2012SPRPremierComp-full.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 2012 Spring builder fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.Variant | Should -Be 'Advanced UI'
      $Info.InstallShieldProjectType | Should -Be 'Advanced UI'
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2012 Spring'
      $Info.InstallShieldRelease.Confidence | Should -Be 'ExactSuiteNamespace'
      $Info.AdvancedUiInfo.ReleaseVersion | Should -Be '2012.2'
      $Info.ProductCode | Should -Be '{D6E404DB-1F4D-4C22-9417-D5785DDCB365}'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Overlay/ISSetupStream'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Suite/AdvancedUI'
      $Info.Warnings | Should -Not -Contain 'Multiple MSI files were extracted, but Setup.ini did not identify which package the bootstrapper launches.'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should route the archived 2013 builder through the unversioned-year suite namespace' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '2013\ArchivedMedia\InstallShield2013PremierComp-full.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 2013 builder fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.Variant | Should -Be 'Advanced UI'
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2013'
      $Info.InstallShieldRelease.Confidence | Should -Be 'ExactSuiteNamespace'
      $Info.AdvancedUiInfo.ReleaseVersion | Should -Be '2013'
      $Info.ProductCode | Should -Be '{EE4F090B-501A-40AB-82F2-4A4F6F79DC49}'
      $Info.SuitePackages.Count | Should -Be 10
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Suite/AdvancedUI'
      $Info.Warnings | Should -BeNullOrEmpty
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should correlate prerequisite references only by exact source identities' {
    InModuleScope InstallShield {
      $Definitions = @(
        [pscustomobject]@{ Path = 'C:\Extracted\DotNetDesktop.prq'; Id = '{11111111-1111-1111-1111-111111111111}'; Description = '.NET Desktop Runtime' },
        [pscustomobject]@{ Path = 'C:\Extracted\Other.prq'; Id = '{22222222-2222-2222-2222-222222222222}'; Description = 'Other Runtime' }
      )
      $References = @(
        [pscustomobject]@{ Name = 'DotNetDesktop' },
        [pscustomobject]@{ Name = 'Missing Runtime' }
      )

      $Evidence = Join-InstallShieldPrerequisiteEvidence -Reference $References -Definition $Definitions
      ($Evidence | Where-Object { $_.Reference.Name -eq 'DotNetDesktop' }).MatchMethod | Should -Be 'ExactIdentityOrName'
      ($Evidence | Where-Object { $_.Reference.Name -eq 'Missing Runtime' }).MatchMethod | Should -Be 'Unresolved'
      ($Evidence | Where-Object MatchMethod -EQ 'UnreferencedDefinition').Definition.Description | Should -Be 'Other Runtime'
    }
  }

It 'Should derive elevation from a selected administrative prerequisite in AFAS PCC' {
    $Fixture = Get-DumplingsTestFixture `
      -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'AFAS.ProfitCommunicationCenter.7.exe') `
      -Uri 'https://profitdownload.afas.nl/download/PCC/PccSetup7.00.exe' `
      -Sha256 '3AD6CB9756673EF53A6E4B5F50E018D12CDA6D7FCF67359A7A658F04848EEC80'
    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.RequestedExecutionLevel | Should -Be 'asInvoker'
      $Info.ElevationRequirement | Should -Be 'elevationRequired'
      $Info.ElevationRequirementEvidence.Confidence | Should -Be 'SelectedPrerequisiteDefinition'
      $Info.PrerequisiteReferences.Name | Should -Contain 'Microsoft .NET Framework 4.8 Full.prq'
      $Info.ElevationRequirementEvidence.SelectedAdministrativePrerequisites.Count | Should -Be 1
      $Info.ElevationRequirementEvidence.SelectedAdministrativePrerequisites[0].HasSilentCommandLine | Should -BeTrue
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should not infer required elevation from the Vertexshare machine MSI' {
    $Fixture = Get-DumplingsTestFixture `
      -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Vertexshare.WebpConverter.exe') `
      -Uri 'https://vertexshare.com/download/webp-converter/webpconverter-win.exe' `
      -Sha256 '2994524E44CF83735F947E238E233A11A599EFAC63FDA05111BE5DE49DC1610A'
    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.RequestedExecutionLevel | Should -Be 'asInvoker'
      $Info.SelectedMsiInfo.Scope | Should -Be 'machine'
      $Info.SelectedMsiInfo.AllowsInstallWithoutElevation | Should -BeFalse
      $Info.ElevationRequirement | Should -BeNullOrEmpty
      $Info.ElevationRequirementEvidence.Confidence | Should -Be 'Unknown'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should evaluate Advanced UI package eligibility without probing the analysis host' {
    $SetupXmlPath = Join-Path $Script:FixtureDirectory 'synthetic-suite-eligibility.xml'
    @'
<Setup SuiteId="{11111111-1111-1111-1111-111111111111}" xmlns="installshield/2026/bootstrap">
  <ARPInfo><DisplayName>Eligibility Suite</DisplayName><Version>1.0</Version><Publisher>Example</Publisher></ARPInfo>
  <SelectionTree>
    <Selection Name="SupportedWindows" Install="Package1 Package2 Package3"><When><All><Platform OSVersion="10.0-" BuildNumber="19041" ProductType="Workstation" /></All></When></Selection>
  </SelectionTree>
  <Parcels>
    <Msi Platform="x64"><UIProperties><Id>Package1</Id><DisplayName>x64 package</DisplayName></UIProperties><Eligible><When><All><Platform Architecture="x64" /></All></When></Eligible></Msi>
    <Exe><UIProperties><Id>Package2</Id><DisplayName>State-dependent package</DisplayName></UIProperties><Eligible><When><Any><Platform Architecture="x86" /><RegistryExists Key="HKLM\Software\Example" /></Any></When></Eligible></Exe>
    <Exe><UIProperties><Id>Package3</Id><DisplayName>Detection-only package</DisplayName></UIProperties><Detect><When><RegistryExists Key="HKLM\Software\Example" /></When></Detect></Exe>
  </Parcels>
</Setup>
'@ | Set-Content -LiteralPath $SetupXmlPath -Encoding utf8
    try {
      $Info = Get-InstallShieldAdvancedUiInfo -Path $SetupXmlPath
      $Eligibility = Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture x64 -OSVersion 10.0 -BuildNumber 22631 -ProductType Workstation

      ($Eligibility | Where-Object PackageId -EQ 'Package1').State | Should -Be 'True'
      ($Eligibility | Where-Object PackageId -EQ 'Package2').State | Should -Be 'Unknown'
      ($Eligibility | Where-Object PackageId -EQ 'Package2').UnknownPredicates | Should -Contain 'RegistryExists'
      # Detect describes installed state and operation planning, not whether the
      # package can be selected on this target platform.
      ($Eligibility | Where-Object PackageId -EQ 'Package3').State | Should -Be 'True'

      $WrongArchitecture = Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture x86 -OSVersion 10.0 -BuildNumber 22631 -ProductType Workstation
      ($WrongArchitecture | Where-Object PackageId -EQ 'Package1').State | Should -Be 'False'

      $OldWindows = Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture x64 -OSVersion 6.1 -BuildNumber 7601 -ProductType Workstation
      $OldWindows.State | Should -Not -Contain 'True'
      $OldWindows.State | Should -Contain 'False'
    } finally {
      Remove-Item -LiteralPath $SetupXmlPath -Force -ErrorAction SilentlyContinue
    }
  }

It 'Should apply InstallShield None semantics to multi-child Not groups' {
    $Condition = [pscustomobject]@{
      Type       = 'Not'
      Attributes = [ordered]@{}
      Value      = $null
      Children   = @(
        [pscustomobject]@{ Type = 'Platform'; Attributes = [ordered]@{ Architecture = 'x86' }; Value = $null; Children = @() },
        [pscustomobject]@{ Type = 'Platform'; Attributes = [ordered]@{ OSVersion = '-6.1' }; Value = $null; Children = @() }
      )
    }

    (Resolve-InstallShieldSuiteCondition -Condition $Condition -Architecture x64 -OSVersion 10.0).State | Should -Be 'True'
    (Resolve-InstallShieldSuiteCondition -Condition $Condition -Architecture x86 -OSVersion 10.0).State | Should -Be 'False'
  }
}
