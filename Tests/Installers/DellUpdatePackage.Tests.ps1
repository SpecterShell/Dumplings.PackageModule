. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
  . (Join-Path $PSScriptRoot '..\Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global
  $Script:Mup = @'
<MUPDefinition xmlns="http://schemas.dell.com/openmanage/cm/2/0/mupdefinition.xsd">
  <packageinformation><name>Test Application</name><version>1.2.3</version><installertype>custom</installertype><packagingtype>executable</packagingtype><mupspecificationversion>2.4.3</mupspecificationversion><supportedoperatingsystems><osidentifier name="Windows10" architecture="arm64" /></supportedoperatingsystems></packageinformation>
  <executable architecture="x86"><executablename>payload.exe</executablename></executable>
  <behaviors><behavior name="unattended"><vendoroption><optionvalue switch="/" requiresvalue="false">s</optionvalue></vendoroption><vendoroption><container><containervalue switch="/" enclose="&quot;">v</containervalue><optionvalue switch="/">qn</optionvalue></container></vendoroption></behavior></behaviors>
  <returncodes><returncodemapping name="REBOOT_REQUIRED"><vendorreturncode>3010</vendorreturncode></returncodemapping></returncodes>
  <inventorymetadata><fullpackageidentifier><msis><msi><upgradecode>{INVENTORY-NOT-PRODUCTCODE}</upgradecode></msi></msis></fullpackageidentifier></inventorymetadata>
</MUPDefinition>
'@
  function New-DellTestZip {
    param ([string]$Path, [System.Collections.IDictionary]$Entries, [switch]$AbsoluteOffsets)
    $Output = [IO.File]::Create($Path)
    try {
      $Output.Write([byte[]]::new(128))
      $ZipStream = $AbsoluteOffsets ? $Output : [IO.MemoryStream]::new()
      $Archive = [IO.Compression.ZipArchive]::new($ZipStream, [IO.Compression.ZipArchiveMode]::Create, $true)
      try {
        foreach ($Key in $Entries.Keys) {
          $Entry = $Archive.CreateEntry($Key)
          $Stream = $Entry.Open()
          try { $Bytes = $Entries[$Key] -is [byte[]] ? $Entries[$Key] : [Text.Encoding]::UTF8.GetBytes([string]$Entries[$Key]); $Stream.Write($Bytes) } finally { $Stream.Dispose() }
        }
      } finally { $Archive.Dispose() }
      if (-not $AbsoluteOffsets) { $ZipStream.Position = 0; $ZipStream.CopyTo($Output); $ZipStream.Dispose() }
    } finally { $Output.Dispose() }
    return $Path
  }
}

Describe 'Dell MUP configuration' {
  It 'replaces default arguments with the untouched passthrough tail' {
    InModuleScope DellUpdatePackage -Parameters @{ Xml = $Script:Mup } {
      $Config = ConvertFrom-DellUpdatePackageConfiguration -Content $Xml
      $Tail = '/clone_wait /s /v"/qn INSTALLDIR=\"C:\App Path\"" /l="vendor.log" /passthrough'
      $Result = Resolve-DellUpdatePackageCommand -Configuration $Config -CommandLine ('"C:\Program Files\setup.exe" /PaSsThRoUgH ' + $Tail)
      $Result.VendorArguments | Should -BeExactly $Tail
      $Result.DefaultVendorArguments | Should -Be '/s /v"/qn"'
      $Result.OptionConflicts.Count | Should -Be 0
      $Result.UsesPassthrough | Should -BeTrue
      $Config.Behaviors[0].Arguments | Should -Be '/s /v"/qn"'
    }
  }

  It 'ignores embedded switch text and distinguishes outer option conflicts' {
    InModuleScope DellUpdatePackage -Parameters @{ Xml = $Script:Mup } {
      $Config = ConvertFrom-DellUpdatePackageConfiguration -Content $Xml
      foreach ($Line in @('"C:\a /passthrough folder\setup.exe" /s', 'setup.exe /label="text /passthrough" /passthrough-extra')) {
        (Resolve-DellUpdatePackageCommand -Configuration $Config -CommandLine $Line).UsesPassthrough | Should -BeFalse
      }
      $Result = Resolve-DellUpdatePackageCommand -Configuration $Config -CommandLine 'setup.exe /l="outer log.txt" /f /passthrough /s /l="vendor log.txt"'
      $Result.OptionConflicts | Should -Be @('/l=outer log.txt', '/f')
      $Result.VendorArguments | Should -Be '/s /l="vendor log.txt"'
      (Resolve-DellUpdatePackageCommand -Configuration $Config -CommandLine 'setup.exe /passthrough').VendorArguments | Should -Be ''
    }
  }

  It 'separates application, launcher, inventory and command evidence' {
    $Info = ConvertFrom-DellUpdatePackageConfiguration -Content $Script:Mup
    $Info.ProductVersion | Should -Be '1.2.3'
    $Info.ExecutableName | Should -Be 'payload.exe'
    $Info.ExecutableArchitecture | Should -Be 'x86'
    $Info.SupportedOperatingSystems[0].Architecture | Should -Be 'arm64'
    $Info.Behaviors[0].Arguments | Should -Be '/s /v"/qn"'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.InventoryUpgradeCodes | Should -Contain '{INVENTORY-NOT-PRODUCTCODE}'
    $Info.VendorReturnCodes[0].Values | Should -Contain '3010'
    $Info.PSObject.Properties.Name | Should -Not -Contain 'ProductCode'
  }

  It 'accepts decoded UTF-16 XML and leaves required parameter values symbolic' {
    $Text = '<?xml version="1.0" encoding="UTF-16LE"?>' + ($Script:Mup -replace '<optionvalue switch="/" requiresvalue="false">s</optionvalue>', '<optionvalue switch="/" requiresvalue="true" valuedelimiter="=" enclose="&quot;">s</optionvalue>')
    $Info = ConvertFrom-DellUpdatePackageConfiguration -Content $Text
    $Info.Behaviors[0].Arguments | Should -Be '/s="<VALUE>" /v"/qn"'
    $Info.SupportsSilentInstallation | Should -BeFalse
  }

  It 'rejects DTDs, wrong namespaces, missing or multiple executable routes' {
    { ConvertFrom-DellUpdatePackageConfiguration -Content ('<!DOCTYPE MUPDefinition [<!ENTITY injected "x">]>' + $Script:Mup) } | Should -Throw
    { ConvertFrom-DellUpdatePackageConfiguration -Content ($Script:Mup -replace 'http://schemas.dell.com/openmanage/cm/2/0/mupdefinition.xsd', 'https://example.test') } | Should -Throw
    { ConvertFrom-DellUpdatePackageConfiguration -Content ($Script:Mup -replace '<executable.*?</executable>', '') } | Should -Throw
    { ConvertFrom-DellUpdatePackageConfiguration -Content ($Script:Mup -replace '</executable>', '</executable><executable><executablename>other.exe</executablename></executable>') } | Should -Throw
  }

  It 'rejects executable traversal and excessive text before allocating XML' {
    { ConvertFrom-DellUpdatePackageConfiguration -Content ($Script:Mup -replace 'payload.exe', '../payload.exe') } | Should -Throw '*escapes*'
    { ConvertFrom-DellUpdatePackageConfiguration -Content ('a' * 4194305) } | Should -Throw '*limit*'
  }

  It 'does not assert unattended support for unknown or duplicated behaviors' {
    $Unknown = ConvertFrom-DellUpdatePackageConfiguration -Content ($Script:Mup -replace '<vendoroption>', '<unknown>' -replace '</vendoroption>', '</unknown>')
    $Unknown.SupportsSilentInstallation | Should -BeFalse
    $Unknown.Behaviors[0].Arguments | Should -BeNullOrEmpty
    $Unknown.Behaviors[0].UnresolvedReason | Should -Match 'Unsupported'
    $Duplicate = ConvertFrom-DellUpdatePackageConfiguration -Content ($Script:Mup -replace '</behaviors>', '<behavior name="unattended"><vendoroption><optionvalue switch="/">q</optionvalue></vendoroption></behavior></behaviors>')
    $Duplicate.SupportsSilentInstallation | Should -BeFalse
  }
}

Describe 'Dell archive and nested evidence' {
  BeforeEach {
    # Mock only the PE identity layer. ZIP parsing, XML, extraction and safety
    # checks use the real implementation with synthetic bounded streams.
    Mock Get-PELayout -ModuleName DellUpdatePackage {
      [pscustomobject]@{ MachineName = 'I386'; Sections = @([pscustomobject]@{ RawOffset = 0; RawSize = 128 }); DataDirectories = [pscustomobject]@{ Certificate = [pscustomobject]@{ Offset = -1; Size = 0 } } }
    }
    Mock Get-PEVersionStringTable -ModuleName DellUpdatePackage { [pscustomobject]@{ OriginalFilename = 'DUPFramework.exe'; FileVersion = '9.9.9' } }
    Mock Get-PERequestedExecutionLevel -ModuleName DellUpdatePackage { 'asInvoker' }
    $Script:ZipPath = New-DellTestZip -Path (Join-Path $TestDrive 'dup.exe') -Entries ([ordered]@{ 'Mup.xml' = $Script:Mup; 'payload.exe' = 'unexecuted'; 'support/readme.txt' = 'support' })
  }

  It 'reads ZIP-relative and file-absolute central-directory offsets' {
    foreach ($Absolute in $false, $true) {
      $Path = New-DellTestZip -Path (Join-Path $TestDrive "offset-$Absolute.exe") -Entries ([ordered]@{ 'mup.xml' = $Script:Mup; 'payload.exe' = 'x' }) -AbsoluteOffsets:$Absolute
      Test-DellUpdatePackage -Path $Path | Should -BeTrue
      $Info = Get-DellUpdatePackageInfo -Path $Path -SkipNestedAnalysis
      $Info.ContainerRoute | Should -Be 'Zip'
      $Info.FrameworkVersion | Should -Be '9.9.9'
      $Info.ProductVersion | Should -Be '1.2.3'
      $Info.PackageArchitecture | Should -Be 'arm64'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.DisplayName | Should -BeNullOrEmpty
      $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.ARP.Unresolved'
      $Info.Diagnostics[0].Scenario | Should -BeNullOrEmpty
      $Info.PSObject.Properties.Name | Should -Not -Contain 'SuggestedManifestFields'
    }
  }

  It 'requires framework identity, not Dell application branding' {
    Mock Get-PEVersionStringTable -ModuleName DellUpdatePackage { [pscustomobject]@{ OriginalFilename = 'DellApplication.exe' } }
    Test-DellUpdatePackage -Path $Script:ZipPath | Should -BeFalse
    Test-DellUpdatePackage -Path $Script:ZipPath -PassThru | Should -BeNullOrEmpty
  }

  It 'reuses one validated container without taking ownership or weakening limits' {
    $Context = Test-DellUpdatePackage -Path $Script:ZipPath -PassThru
    try {
      Mock Open-DellUpdatePackage -ModuleName DellUpdatePackage { throw 'A borrowed context must not reopen the container.' }
      $First = Get-DellUpdatePackageInfo -Path $Script:ZipPath -SkipNestedAnalysis -AnalysisContext $Context
      $Second = Get-DellUpdatePackageInfo -Path $Script:ZipPath -SkipNestedAnalysis -AnalysisContext $Context
      $First.PayloadFiles | Should -HaveCount 3
      $Second.ProductVersion | Should -Be $First.ProductVersion
      Should -Invoke Get-PEVersionStringTable -ModuleName DellUpdatePackage -Times 1 -Exactly
      $Context.ArchiveContext.SourceStream.CanRead | Should -BeTrue
      { Get-DellUpdatePackageInfo -Path $Script:ZipPath -AnalysisContext $Context -MaximumExpandedBytes 10 } | Should -Throw '*byte limit*'
      $Other = New-DellTestZip -Path (Join-Path $TestDrive 'other.exe') -Entries ([ordered]@{ 'mup.xml' = $Script:Mup; 'payload.exe' = 'other' })
      { Get-DellUpdatePackageInfo -Path $Other -AnalysisContext $Context } | Should -Throw '*different source*'
      $Context.ArchiveContext.SourceStream.CanRead | Should -BeTrue
      Should -Invoke Open-DellUpdatePackage -ModuleName DellUpdatePackage -Times 0 -Exactly
    } finally { Close-InstallerArchiveRange -Context $Context.ArchiveContext }
    { Get-DellUpdatePackageInfo -Path $Script:ZipPath -AnalysisContext $Context } | Should -Throw '*closed*'
  }

  It 'passes the validated probe context into the real Dell EXE parser' {
    $Context = Test-DellUpdatePackage -Path $Script:ZipPath -PassThru
    Mock Open-DellUpdatePackage -ModuleName DellUpdatePackage { throw 'The analyzer must reuse its probe.' }
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage {
      [pscustomobject]@{ Family = 'Test'; Info = [pscustomobject]@{ ProductCode = 'Selected'; Diagnostics = @() } }
    }
    try {
      $Result = @(InModuleScope InstallerAnalyzer -Parameters @{ Path = $Script:ZipPath; Context = $Context } {
          Invoke-InstallerExeParser -InstallerPath $Path -ExtractEmbeddedMsi $true -FamilyCandidates @([pscustomobject]@{ Family = 'Dell Update Package'; Confidence = 'high' }) -ParserContexts @{ 'Dell Update Package' = $Context }
        })
      $Result | Should -HaveCount 1
      $Result[0].Success | Should -BeTrue
      $Result[0].Result.Metadata.ProductCode | Should -Be 'Selected'
      $Context.ArchiveContext.SourceStream.CanRead | Should -BeTrue
      Should -Invoke Open-DellUpdatePackage -ModuleName DellUpdatePackage -Times 0 -Exactly
    } finally { Close-InstallerArchiveRange -Context $Context.ArchiveContext }
  }

  It 'releases operation-owned contexts after analyzer success or failure' -TestCases @(
    @{ Fail = $false }
    @{ Fail = $true }
  ) {
    param($Fail)
    $Context = Test-DellUpdatePackage -Path $Script:ZipPath -PassThru
    Mock Get-InstallerFileTypeEvidence -ModuleName InstallerAnalyzer { [pscustomobject]@{ Type = 'PE' } }
    Mock Read-InstallerStringWindows -ModuleName InstallerAnalyzer { '' }
    Mock Get-InstallerGenericExeFamilyCandidate -ModuleName InstallerAnalyzer { }
    Mock Get-InstallerWrapperDiagnostic -ModuleName InstallerAnalyzer { }
    Mock Get-InstallerStructuralExeFamilyCandidate -ModuleName InstallerAnalyzer {
      $ParserContexts['Dell Update Package'] = $Context
      [pscustomobject]@{ Family = 'Dell Update Package'; Confidence = 'high'; MatchedMarkers = @('validated container') }
    }
    Mock Invoke-InstallerExeParser -ModuleName InstallerAnalyzer {
      $ParserContexts['Dell Update Package'] | Should -Be $Context
      if ($Fail) { throw 'Injected parser failure.' }
      [pscustomobject]@{ Name = 'Dell Update Package'; Success = $true; Result = [pscustomobject]@{ Family = 'Dell Update Package'; Diagnostics = @() } }
    }
    try {
      if ($Fail) { { Get-InstallerAnalysis -Path $Script:ZipPath } | Should -Throw '*Injected parser failure*' }
      else {
        $Analysis = Get-InstallerAnalysis -Path $Script:ZipPath
        $Analysis.DetectedFamilies.Family | Should -Contain 'Dell Update Package'
        $Analysis.PSObject.Properties.Name | Should -Not -Contain 'ParserContexts'
      }
      $Context.ArchiveContext.SourceStream.CanRead | Should -BeFalse
    } finally { Close-InstallerArchiveRange -Context $Context.ArchiveContext }
  }

  It 'uses catalog spelling for a case-insensitive MUP payload match' {
    $Path = New-DellTestZip -Path (Join-Path $TestDrive 'case.exe') -Entries ([ordered]@{ 'mup.xml' = $Script:Mup; 'Payload.EXE' = 'x' })
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage {
      [IO.Path]::GetFileName($Path) | Should -BeExactly 'Payload.EXE'
      Test-Path -LiteralPath $Path | Should -BeTrue
      [pscustomobject]@{ Family = 'Test'; Info = [pscustomobject]@{ ProductCode = 'Selected'; Diagnostics = @() } }
    }
    (Get-DellUpdatePackageInfo -Path $Path).ProductCode | Should -Be 'Selected'
    Should -Invoke Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage -Times 1 -Exactly
  }

  It 'stages only a directly selected MSI for database metadata analysis' {
    $Mup = $Script:Mup -replace 'payload.exe', '[Payload].msi'
    $Path = New-DellTestZip -Path (Join-Path $TestDrive 'msi.exe') -Entries ([ordered]@{ 'mup.xml' = $Mup; '[Payload].MSI' = 'msi'; 'unrelated.txt' = 'support'; 'other.msi' = 'other'; 'support/[Payload].MSI' = 'same name' })
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage {
      @(Get-ChildItem -LiteralPath $WorkPath -File -Recurse).Count | Should -Be 1
      [IO.Path]::GetFileName($Path) | Should -BeExactly '[Payload].MSI'
      [pscustomobject]@{ Family = 'MSI'; Info = [pscustomobject]@{ ProductCode = 'Selected'; Diagnostics = @() } }
    }
    (Get-DellUpdatePackageInfo -Path $Path).ProductCode | Should -Be 'Selected'
  }

  It 'extracts all files or one selected pattern using PowerShell-relative paths' {
    Push-Location $TestDrive
    try {
      $Before = [Environment]::CurrentDirectory
      [Environment]::CurrentDirectory = [IO.Path]::GetTempPath()
      $Files = @(Expand-DellUpdatePackage -Path '.\dup.exe' -DestinationPath '.\all' -CollisionAction Error)
      $Files.Count | Should -Be 3
      $Files.FullName | Should -Contain (Join-Path $TestDrive 'all\support\readme.txt')
      @(Expand-DellUpdatePackage -Path '.\dup.exe' -DestinationPath '.\selected' -Name '*.xml' -CollisionAction Error).Count | Should -Be 1
    } finally { [Environment]::CurrentDirectory = $Before; Pop-Location }
  }

  It 'prompts only after a collision and supports Error, Skip, Overwrite and Rename' {
    Mock Read-Host -ModuleName FileSystem { 'Skip' }
    $Destination = Join-Path $TestDrive 'collision'
    @(Expand-DellUpdatePackage -Path $Script:ZipPath -DestinationPath $Destination).Count | Should -Be 3
    Should -Invoke Read-Host -ModuleName FileSystem -Times 0 -Exactly
    { Expand-DellUpdatePackage -Path $Script:ZipPath -DestinationPath $Destination -CollisionAction Error } | Should -Throw '*already exists*'
    @(Expand-DellUpdatePackage -Path $Script:ZipPath -DestinationPath $Destination -CollisionAction Skip).Count | Should -Be 0
    @(Expand-DellUpdatePackage -Path $Script:ZipPath -DestinationPath $Destination -CollisionAction Overwrite).Count | Should -Be 3
    @(Expand-DellUpdatePackage -Path $Script:ZipPath -DestinationPath $Destination -CollisionAction Rename).Count | Should -Be 3
  }

  It 'rejects catalog traversal, canonical duplicates, entry/byte bounds and malformed XML' {
    $Bad = New-DellTestZip -Path (Join-Path $TestDrive 'bad.exe') -Entries ([ordered]@{ 'mup.xml' = $Script:Mup; '../escape.exe' = 'x' })
    { Expand-DellUpdatePackage -Path $Bad -DestinationPath (Join-Path $TestDrive 'unsafe') } | Should -Throw '*escapes*'
    $Duplicate = New-DellTestZip -Path (Join-Path $TestDrive 'dup-path.exe') -Entries ([ordered]@{ 'mup.xml' = $Script:Mup; 'dir/payload.exe' = 'x'; 'dir\payload.exe' = 'y' })
    { Expand-DellUpdatePackage -Path $Duplicate -DestinationPath (Join-Path $TestDrive 'duplicates') } | Should -Throw '*duplicate*'
    { Expand-DellUpdatePackage -Path $Script:ZipPath -DestinationPath (Join-Path $TestDrive 'entries') -MaximumEntries 1 } | Should -Throw '*entry limit*'
    { Get-DellUpdatePackageInfo -Path $Script:ZipPath -MaximumExpandedBytes 10 } | Should -Throw '*byte limit*'
    $Malformed = New-DellTestZip -Path (Join-Path $TestDrive 'xml.exe') -Entries ([ordered]@{ 'mup.xml' = '<broken>'; 'payload.exe' = 'x' })
    Test-DellUpdatePackage -Path $Malformed | Should -BeFalse
  }

  It 'preserves ARP uncertainty when the selected file is absent or parsing fails' {
    $Missing = New-DellTestZip -Path (Join-Path $TestDrive 'missing.exe') -Entries ([ordered]@{ 'mup.xml' = $Script:Mup; 'unrelated.exe' = 'x' })
    $Info = Get-DellUpdatePackageInfo -Path $Missing
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.Payload.Missing'
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage { throw 'Synthetic nested failure' }
    $Failed = Get-DellUpdatePackageInfo -Path $Script:ZipPath
    $Failed.ProductCode | Should -BeNullOrEmpty
    $Failed.Diagnostics.Id | Should -Contain 'DellUpdatePackage.Nested.Incomplete'
  }

  It 'keeps validated Dell structure when optional package.xml is invalid or oversized' {
    foreach ($Content in @('<broken>', '<OtherRoot />', ('x' * 4194305))) {
      $Path = New-DellTestZip -Path (Join-Path $TestDrive 'optional.exe') -Entries ([ordered]@{ 'mup.xml' = $Script:Mup; 'payload.exe' = 'x'; 'package.xml' = $Content })
      Test-DellUpdatePackage -Path $Path | Should -BeTrue
      $Info = Get-DellUpdatePackageInfo -Path $Path -SkipNestedAnalysis
      $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.PackageMetadata.Invalid'
      $Info.UnresolvedFields | Should -Contain 'ReleaseNotes'
      $Info.PackageMetadata | Should -BeNullOrEmpty
    }
  }

  It 'uses caller arguments for nested analysis and withholds overridden defaults' {
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage {
      [pscustomobject]@{ Family = 'MSI'; Info = [pscustomobject]@{ ProductCode = '{DEFAULT}'; DisplayName = 'Default ARP'; Scope = 'machine'; WritesAppsAndFeaturesEntry = $true; Diagnostics = @() } }
    }
    $Tail = '/s /v"/qn ALLUSERS=2 ARPSYSTEMCOMPONENT=1"'
    $Info = Get-DellUpdatePackageInfo -Path $Script:ZipPath -CommandLine ('"setup.exe" /passthrough ' + $Tail)
    $Info.CommandBehavior.Source | Should -Be 'Passthrough'
    $Info.ExecutedPayloads[0].Arguments | Should -BeExactly $Tail
    $Info.Scope | Should -BeNullOrEmpty
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.NestedInstallerInfo.ProductCode | Should -Be '{DEFAULT}'
    $Info.SupportsSilentInstallation | Should -BeNullOrEmpty
    $Info.InstallerSwitches.Count | Should -Be 0
    $Info.InstallModes.Count | Should -Be 0
    $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.Passthrough.UnattendedUnproven'
    $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.Nested.CommandOverrides'
    Should -Invoke Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage -Times 1 -Exactly -ParameterFilter { $Arguments -ceq '/s /v"/qn ALLUSERS=2 ARPSYSTEMCOMPONENT=1"' }
    $Conflict = Get-DellUpdatePackageInfo -Path $Script:ZipPath -SkipNestedAnalysis -CommandLine 'setup.exe /l=outer.log /passthrough /s'
    $Conflict.Diagnostics.Id | Should -Contain 'DellUpdatePackage.Passthrough.OptionConflict'
  }

  It 'retains unsupported MUP evidence without warning about replaced commands' {
    $Unknown = $Script:Mup -replace '<vendoroption>', '<unknown>' -replace '</vendoroption>', '</unknown>'
    $Path = New-DellTestZip -Path (Join-Path $TestDrive 'unknown-command.exe') -Entries ([ordered]@{ 'mup.xml' = $Unknown; 'payload.exe' = 'x' })
    (Get-DellUpdatePackageInfo -Path $Path -SkipNestedAnalysis).Diagnostics.Id | Should -Contain 'DellUpdatePackage.Command.Unsupported'
    $Info = Get-DellUpdatePackageInfo -Path $Path -SkipNestedAnalysis -CommandLine 'setup.exe /passthrough /s'
    $Info.Diagnostics.Id | Should -Not -Contain 'DellUpdatePackage.Command.Unsupported'
    $Info.Configuration.Behaviors[0].UnresolvedReason | Should -Match 'Unsupported'
    $Info.CommandBehavior.VendorArguments | Should -Be '/s'
  }

  It 'withholds unmodified nested ARP defaults when configured MSI properties override them' {
    $Override = $Script:Mup -replace '>s</optionvalue>', '>s ALLUSERS=2 MSIINSTALLPERUSER=1 ARPSYSTEMCOMPONENT=1</optionvalue>'
    $Path = New-DellTestZip -Path (Join-Path $TestDrive 'override.exe') -Entries ([ordered]@{ 'mup.xml' = $Override; 'payload.exe' = 'x' })
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage {
      [pscustomobject]@{ Family = 'MSI'; Info = [pscustomobject]@{ ProductCode = '{DEFAULT}'; DisplayName = 'Default ARP'; Scope = 'machine'; WritesAppsAndFeaturesEntry = $true; Diagnostics = @() } }
    }
    $Info = Get-DellUpdatePackageInfo -Path $Path
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.Scope | Should -BeNullOrEmpty
    $Info.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $Info.NestedInstallerInfo.ProductCode | Should -Be '{DEFAULT}'
    $Info.UnresolvedFields | Should -Contain 'ProductCode'
    $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.Nested.CommandOverrides'
    InModuleScope WinGetManifestUpdate -Parameters @{ Info = $Info } {
      $Entry = [ordered]@{ Architecture = 'x64'; InstallerType = 'exe'; ProductCode = '{EXISTING}'; AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Existing ARP'; ProductCode = '{EXISTING}' }) }
      $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject @($Info) -InstallerType exe -OldInstaller $Entry
      Set-WinGetInstallerManifestMetadata -Installer $Entry -OldInstaller $Entry -InstallerEntry ([ordered]@{}) -Metadata $Metadata -ParserName 'Dell Update Package' -ConfirmedFamily -DiagnosticCollection ([Collections.Generic.List[object]]::new())
      $Entry.ProductCode | Should -Be '{EXISTING}'
      $Entry.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Existing ARP'
    }
  }

  It 'projects only selected nested ARP values and cleans staging after analysis' {
    $Staging = Join-Path $TestDrive 'staging'
    Mock New-TempFolder -ModuleName DellUpdatePackage { New-Item -Path (Join-Path $TestDrive 'staging') -ItemType Directory -Force | Select-Object -ExpandProperty FullName }
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage {
      [pscustomobject]@{ Family = 'MSI'; Info = [pscustomobject]@{ ProductCode = '{NESTED}'; UpgradeCode = '{UPGRADE}'; DisplayName = 'Nested ARP'; DisplayVersion = '1.2.3.4'; Publisher = 'Vendor'; Scope = 'machine'; WritesAppsAndFeaturesEntry = $true; AppsAndFeaturesProductCode = '{NESTED}'; AppsAndFeaturesInstallerType = 'wix'; Diagnostics = @(); UnresolvedFields = @('CustomAction') } }
    }
    $Info = Get-DellUpdatePackageInfo -Path $Script:ZipPath
    $Info.ProductCode | Should -Be '{NESTED}'
    $Info.DisplayName | Should -Be 'Nested ARP'
    $Info.ProductVersion | Should -Be '1.2.3'
    $Info.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'wix'
    $Info.UnresolvedFields | Should -Contain 'CustomAction'
    Test-Path -LiteralPath $Staging | Should -BeFalse
  }

  It 'reuses parsed InstallShield metadata and preserves suite-owned ARP rather than selecting an MSI' {
    Mock Test-DellUpdatePackage -ModuleName DellUpdatePackage { $false }
    Mock Get-InstallShieldInfo -ModuleName DellUpdatePackage { throw 'Must not parse the nested container twice' }
    Mock Get-InstallerAnalysis -ModuleName DellUpdatePackage {
      [pscustomobject]@{ ParserResults = @([pscustomobject]@{ Success = $true; Result = [pscustomobject]@{
              Family = 'InstallShield'; MsiInfo = $null
              Metadata = [pscustomobject]@{ Variant = 'Advanced UI'; HasMsi = $true; ProductCode = '{SUITE}'; Diagnostics = @() }
            }
          })
      }
    }
    InModuleScope DellUpdatePackage -Parameters @{ Path = $Script:ZipPath; WorkPath = $TestDrive } {
      $Info = Get-DellUpdatePackageNestedInfo -Path $Path -WorkPath $WorkPath -Budget ([pscustomobject]@{ Remaining = 1024 }) -Diagnostics ([Collections.Generic.List[object]]::new())
      $Info.Info.ProductCode | Should -Be '{SUITE}'
      $Info.Family | Should -Be 'InstallShield'
    }
    Should -Invoke Get-InstallerAnalysis -ModuleName DellUpdatePackage -Times 1 -Exactly
    Should -Invoke Get-InstallShieldInfo -ModuleName DellUpdatePackage -Times 0 -Exactly
  }

  It 'forwards MUP arguments into NSIS simulation without suppressing resolved metadata' {
    Mock Test-DellUpdatePackage -ModuleName DellUpdatePackage { $false }
    Mock Get-InstallerAnalysis -ModuleName DellUpdatePackage {
      [pscustomobject]@{ ParserResults = @([pscustomobject]@{ Success = $true; Result = [pscustomobject]@{ Family = 'NSIS/Nullsoft'; Metadata = [pscustomobject]@{ ProductCode = 'Machine'; Diagnostics = @() } } }) }
    }
    InModuleScope DellUpdatePackage -Parameters @{ Path = $Script:ZipPath; WorkPath = $TestDrive } {
      (Get-DellUpdatePackageNestedInfo -Path $Path -WorkPath $WorkPath -Arguments '/S /ALLUSERS' -Budget ([pscustomobject]@{ Remaining = 1024 }) -Diagnostics ([Collections.Generic.List[object]]::new())).Info.ProductCode | Should -Be 'Machine'
      @(Get-DellUpdatePackageCommandAffectedField -Arguments '/S /ALLUSERS' -Family 'NSIS/Nullsoft').Count | Should -Be 0
    }
    Should -Invoke Get-InstallerAnalysis -ModuleName DellUpdatePackage -Times 1 -Exactly -ParameterFilter { $CommandLine.EndsWith(' /S /ALLUSERS') }
  }

  It 'rejects a fourth SFX layer before allocating or extracting its output' {
    Mock Test-DellUpdatePackage -ModuleName DellUpdatePackage { $false }
    Mock Get-InstallerAnalysis -ModuleName DellUpdatePackage {
      [pscustomobject]@{ ParserResults = @([pscustomobject]@{ Success = $true; Result = [pscustomobject]@{
              Family = '7z SFX'; Metadata = [pscustomobject]@{ Diagnostics = @(); ExecutedPayloads = @('child.exe'); ExecutedPayload = 'child.exe' }
            }
          })
      }
    }
    Mock Export-InstallerArchiveSelection -ModuleName DellUpdatePackage { throw 'Fourth layer must not be extracted' }
    InModuleScope DellUpdatePackage -Parameters @{ Path = $Script:ZipPath; WorkPath = $TestDrive } {
      { Get-DellUpdatePackageNestedInfo -Path $Path -WorkPath $WorkPath -Depth 3 -Budget ([pscustomobject]@{ Remaining = 1024 }) -Diagnostics ([Collections.Generic.List[object]]::new()) } | Should -Throw '*three-layer limit*'
    }
    Should -Invoke Export-InstallerArchiveSelection -ModuleName DellUpdatePackage -Times 0 -Exactly
  }

  It 'retains catalog spelling when following a configured SFX child' -ForEach @(
    @{ ChildName = 'child.exe' }
    @{ ChildName = './child.exe' }
  ) {
    Mock Test-DellUpdatePackage -ModuleName DellUpdatePackage { $false }
    Mock Get-InstallerAnalysis -ModuleName DellUpdatePackage {
      $Result = if ([IO.Path]::GetFileName($Path) -ceq 'Child.EXE') {
        [pscustomobject]@{ Family = 'MSI'; Metadata = [pscustomobject]@{ ProductCode = 'Selected'; Diagnostics = @() } }
      } else {
        [pscustomobject]@{ Family = '7z SFX'; Metadata = [pscustomobject]@{ Diagnostics = @(); ArchiveOffset = 128L; ExecutedPayloads = @($ChildName); ExecutedPayload = $ChildName; PayloadArguments = '/s' } }
      }
      [pscustomobject]@{ ParserResults = @([pscustomobject]@{ Success = $true; Result = $Result }) }
    }
    Mock Get-EmbeddedSevenZipArchiveRange -ModuleName DellUpdatePackage { [pscustomobject]@{ Offset = 128L; Length = 20L } }
    Mock Open-InstallerArchiveRange -ModuleName DellUpdatePackage { [pscustomobject]@{ Archive = 'Synthetic' } }
    Mock Close-InstallerArchiveRange -ModuleName DellUpdatePackage { }
    Mock Export-InstallerArchiveSelection -ModuleName DellUpdatePackage {
      $null = New-Item -ItemType Directory -Path $DestinationPath -Force
      $Child = Join-Path $DestinationPath 'Child.EXE'
      [IO.File]::WriteAllBytes($Child, [byte[]](1, 2, 3))
      [pscustomobject]@{ Files = @([IO.FileInfo]::new($Child)); ExpandedBytes = 3L }
    }
    InModuleScope DellUpdatePackage -Parameters @{ Path = $Script:ZipPath; WorkPath = $TestDrive; ChildName = $ChildName } {
      $Info = Get-DellUpdatePackageNestedInfo -Path $Path -WorkPath $WorkPath -Budget ([pscustomobject]@{ Remaining = 1024 }) -Diagnostics ([Collections.Generic.List[object]]::new())
      $Info.Info.ProductCode | Should -Be 'Selected'
      $Info.ExecutionChain[0].SelectedPayload | Should -Be $ChildName
    }
    Should -Invoke Get-InstallerAnalysis -ModuleName DellUpdatePackage -Times 1 -Exactly -ParameterFilter { [IO.Path]::GetFileName($Path) -ceq 'Child.EXE' }
  }

  It 'marks transforms, identity and path overrides without matching unrelated property names' {
    InModuleScope DellUpdatePackage {
      $Fields = @(Get-DellUpdatePackageCommandAffectedField -Arguments '/v"/qn TRANSFORMS=custom.mst INSTALLDIR=C:\Custom ProductName=New"' -Family 'InstallShield')
      $Fields | Should -Contain 'ProductCode'
      $Fields | Should -Contain 'DefaultInstallLocation'
      $Fields | Should -Contain 'DisplayName'
      $Fields | Should -Contain 'UpgradeCode'
      $Fields | Should -Contain 'UninstallString'
      $Fields | Should -Contain 'QuietUninstallString'
      $Fields | Should -Contain 'DisplayIcon'
      $Fields | Should -Contain 'Protocols'
      $Fields | Should -Contain 'FileExtensions'
      $Fields | Should -Contain 'RegistryAssociationInfo'
      @(Get-DellUpdatePackageCommandAffectedField -Arguments 'NOTALLUSERS=1 /v/qn' -Family 'InstallShield').Count | Should -Be 0
      $IdentityFields = @(Get-DellUpdatePackageCommandAffectedField -Arguments 'ProductCode={OVERRIDE}' -Family MSI)
      $IdentityFields | Should -Contain 'UninstallString'
      $IdentityFields | Should -Contain 'QuietUninstallString'
    }
  }

  It 'derives package-specific directory overrides from selected MSI evidence' -ForEach @(
    @{ Nested = [pscustomobject]@{ InstallLocationProperty = 'APPDIR' } }
    @{ Nested = [pscustomobject]@{ InstallLocationSwitch = 'APPDIR="<INSTALLPATH>"' } }
  ) {
    InModuleScope DellUpdatePackage -Parameters @{ Nested = $Nested } {
      $Fields = @(Get-DellUpdatePackageCommandAffectedField -Arguments '/v"/qn APPDIR=\"C:\Custom App\""' -Family InstallShield -NestedInfo $Nested)
      $Fields | Should -Contain 'DefaultInstallLocation'
      $Fields | Should -Contain 'DisplayIcon'
      $Fields | Should -Contain 'UninstallString'
      $Fields | Should -Contain 'RegistryAssociationInfo'
      $Fields | Should -Not -Contain 'ProductCode'
      @(Get-DellUpdatePackageCommandAffectedField -Arguments 'NOTAPPDIR=C:\Other' -Family MSI -NestedInfo $Nested).Count | Should -Be 0
    }
  }

  It 'withholds paths and associations changed by a custom directory without modifying raw nested facts' {
    Mock Get-DellUpdatePackageNestedInfo -ModuleName DellUpdatePackage {
      [pscustomobject]@{ Family = 'MSI'; Info = [pscustomobject]@{
          ProductCode = '{DEFAULT}'; InstallLocationProperty = 'APPDIR'; DefaultInstallLocation = 'C:\Default'; DisplayIcon = 'C:\Default\app.exe'
          UninstallString = 'C:\Default\uninstall.exe'; QuietUninstallString = 'C:\Default\uninstall.exe /S'
          Protocols = @('test'); FileExtensions = @('test'); RegistryAssociationInfo = [pscustomobject]@{ Command = 'C:\Default\app.exe' }; Diagnostics = @()
        }
      }
    }
    $Info = Get-DellUpdatePackageInfo -Path $Script:ZipPath -CommandLine 'setup.exe /passthrough /qn APPDIR="C:\Custom App"'
    $Info.ProductCode | Should -Be '{DEFAULT}'
    $Info.DefaultInstallLocation | Should -BeNullOrEmpty
    $Info.DisplayIcon | Should -BeNullOrEmpty
    $Info.UninstallString | Should -BeNullOrEmpty
    $Info.QuietUninstallString | Should -BeNullOrEmpty
    $Info.Protocols.Count | Should -Be 0
    $Info.FileExtensions.Count | Should -Be 0
    $Info.RegistryAssociationInfo | Should -BeNullOrEmpty
    $Info.NestedInstallerInfo.DefaultInstallLocation | Should -Be 'C:\Default'
    $Info.NestedInstallerInfo.Protocols | Should -Be @('test')
    $Info.UnresolvedFields | Should -Contain 'DisplayIcon'
  }

  It 'passes the virtual vendor command from the analyzer into NSIS without execution' {
    Mock Get-NSISInfo -ModuleName InstallerAnalyzer {
      [pscustomobject]@{
        DisplayVersion = '1.2.3'; DisplayName = 'Application'; Publisher = 'Publisher'; ProductCode = 'Machine'; Scope = 'machine'
        AppsAndFeaturesEntries = @(); AppsAndFeaturesEntryEvidence = @(); HasLocalizedAppsAndFeaturesEntries = $false
        Diagnostics = @(); Protocols = @(); FileExtensions = @(); RegistryAssociationInfo = $null
      }
    }
    InModuleScope InstallerAnalyzer -Parameters @{ Path = $Script:ZipPath } {
      $Result = @(Invoke-InstallerExeParser -InstallerPath $Path -ExtractEmbeddedMsi $false -FamilyCandidates @([pscustomobject]@{ Family = 'NSIS/Nullsoft'; Confidence = 'high' }) -CommandLine '"payload.exe" /S /ALLUSERS')
      $Result.Count | Should -Be 1
      $Result[0].Success | Should -BeTrue
      $Result[0].Result.ProductCode | Should -Be 'Machine'
    }
    Should -Invoke Get-NSISInfo -ModuleName InstallerAnalyzer -Times 1 -Exactly -ParameterFilter { $CommandLine -ceq '"payload.exe" /S /ALLUSERS' -and $FileSystemComplete }
  }

  It 'rejects truncated archives and archive ranges crossing a certificate table' {
    $Bytes = [IO.File]::ReadAllBytes($Script:ZipPath)
    [IO.File]::WriteAllBytes($Script:ZipPath, $Bytes[0..($Bytes.Length - 15)])
    Test-DellUpdatePackage -Path $Script:ZipPath | Should -BeFalse
    $Script:ZipPath = New-DellTestZip -Path $Script:ZipPath -Entries ([ordered]@{ 'mup.xml' = $Script:Mup })
    Mock Get-PELayout -ModuleName DellUpdatePackage {
      [pscustomobject]@{ MachineName = 'I386'; Sections = @([pscustomobject]@{ RawOffset = 0; RawSize = 128 }); DataDirectories = [pscustomobject]@{ Certificate = [pscustomobject]@{ Offset = 180; Size = 100 } } }
    }
    { Get-DellUpdatePackageInfo -Path $Script:ZipPath -SkipNestedAnalysis } | Should -Throw '*certificate*'
  }

  It 'rejects certificate lengths outside the file' {
    Mock Get-PELayout -ModuleName DellUpdatePackage {
      [pscustomobject]@{ MachineName = 'I386'; Sections = @([pscustomobject]@{ RawOffset = 0; RawSize = 128 }); DataDirectories = [pscustomobject]@{ Certificate = [pscustomobject]@{ Offset = [long]::MaxValue; Size = 100 } } }
    }
    { Get-DellUpdatePackageInfo -Path $Script:ZipPath -SkipNestedAnalysis } | Should -Throw '*certificate table*'
  }
}

Describe 'Dell preferred WinGet command route' {
  BeforeAll {
    function New-DellSuggestionMetadata {
      param ([string]$Family, $Nested, [string]$Arguments = '/s', $Wrapper = $null)
      [pscustomobject]@{
        InstallerType = 'exe'; NestedFamily = $Family; NestedInstallerInfo = $Nested; NestedWrapperInfo = $Wrapper; ExecutionChain = @()
        CommandBehavior = [pscustomobject]@{ UsesPassthrough = $false; VendorArguments = $Arguments }
        InstallerSwitches = [ordered]@{ Silent = '/s'; SilentWithProgress = '/s'; Log = '/l="<LOGPATH>"' }
        InstallModes = @('interactive', 'silent')
      }
    }
  }

  It 'uses InstallShield defaults and exposes configured properties and wait flags only as an alternative' {
    $Metadata = New-DellSuggestionMetadata -Family InstallShield -Nested ([pscustomobject]@{ InstallerType = 'msi'; InstallLocationSwitch = 'APPDIR="<INSTALLPATH>"' }) -Wrapper ([pscustomobject]@{ InstallerType = 'exe'; InstallShieldProjectType = 'Basic MSI' }) -Arguments '/clone_wait /s /v"/qn ALLUSERS=1 TRANSFORMS=\"custom transform.mst\""'
    $Before = $Metadata | ConvertTo-Json -Depth 8 -Compress
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Result = Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })
      $Fields = $Result.ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/passthrough /S /V/quiet /V/norestart'
      $Fields.InstallerSwitches.SilentWithProgress | Should -Be '/passthrough /S /V/passive /V/norestart'
      $Fields.InstallerSwitches.Interactive | Should -Be '/passthrough'
      $Fields.InstallerSwitches.Log | Should -Be '/V"/log \"<LOGPATH>\""'
      $Fields.InstallerSwitches.InstallLocation | Should -Be '/V"APPDIR=\"<INSTALLPATH>\""'
      $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
      $Alternative = @($Result.ManifestVariants | Where-Object Name -EQ EmbeddedMup)[0]
      $Alternative.ManifestFields.InstallerSwitches.Silent | Should -Be '/s'
      $Alternative.ManifestFields.InstallerSwitches.Log | Should -Be '/l="<LOGPATH>"'
      $Alternative.ManifestFields.InstallModes | Should -Be @('interactive', 'silent')
      $Alternative.Evidence.CommandSource | Should -Be 'MupUnattended'
      $Alternative.Evidence.VendorArguments | Should -BeExactly $Metadata.CommandBehavior.VendorArguments
      $Alternative.ManifestFields.ExpectedReturnCodes.InstallerReturnCode | Should -Be @(2, 4, 5, 6)
      $Fields.InstallModes | Should -Contain 'silentWithProgress'
      $Fields.ExpectedReturnCodes.InstallerReturnCode | Should -Be @(2, 4, 5, 6)
      $Result.SuggestedNextSteps -join ' ' | Should -Match 'EmbeddedMup.*required package-specific options'
      # WinGet places the mode first, then Log and Custom, then location.
      foreach ($Mode in @('Silent', 'SilentWithProgress', 'Interactive')) {
        $Line = 'setup.exe ' + $Fields.InstallerSwitches[$Mode] + ' ' + $Fields.InstallerSwitches.Log + ' ' + $Fields.InstallerSwitches.InstallLocation
        $Command = & (Get-Module DellUpdatePackage) { param($Line) Resolve-DellUpdatePackageCommand -Configuration ([pscustomobject]@{ Behaviors = @() }) -CommandLine $Line } $Line
        $Command.OptionConflicts.Count | Should -Be 0
        $Command.VendorArguments | Should -Match '/V.*<LOGPATH>'
        $Command.VendorArguments | Should -Match '/V.*APPDIR='
      }
      $Schema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion '1.12.0'
      $Entry = Merge-WinGetManifestDictionary -Base ([ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64 }) -Override (ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Fields)
      (Get-YamlSchemaValidationResult -InputObject $Entry -Schema $Schema.definitions.Installer -RootSchema $Schema).IsValid | Should -BeTrue
      $AlternativeEntry = Merge-WinGetManifestDictionary -Base ([ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64 }) -Override (ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Alternative.ManifestFields)
      (Get-YamlSchemaValidationResult -InputObject $AlternativeEntry -Schema $Schema.definitions.Installer -RootSchema $Schema -ValidatePropertyNames).IsValid | Should -BeTrue
    }
    ($Metadata | ConvertTo-Json -Depth 8 -Compress) | Should -BeExactly $Before
  }

  It 'uses known MSI defaults with the actual directory property without package-specific arguments' {
    $Metadata = New-DellSuggestionMetadata -Family MSI -Nested ([pscustomobject]@{ InstallerType = 'wix'; InstallLocationSwitch = 'APPLICATIONROOT="<INSTALLPATH>"' }) -Arguments '/qn REINSTALL=all REINSTALLMODE=vomus REBOOT=REALLYSUPPRESS'
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/passthrough /quiet /norestart'
      $Fields.InstallerSwitches.InstallLocation | Should -Be 'APPLICATIONROOT="<INSTALLPATH>"'
      $Fields.InstallerSwitches.Log | Should -Be '/log "<LOGPATH>"'
      $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
    }
  }

  It 'does not invent an MSI directory property when only logging is known' {
    $Metadata = New-DellSuggestionMetadata -Family MSI -Nested ([pscustomobject]@{ InstallerType = 'msi' }) -Arguments '/quiet /norestart'
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Match '^/passthrough '
      $Fields.InstallerSwitches.Contains('InstallLocation') | Should -BeFalse
      $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
    }
  }

  It 'uses case-correct NSIS defaults without retaining a configured scope option' {
    $Metadata = New-DellSuggestionMetadata -Family 'NSIS/Nullsoft' -Nested ([pscustomobject]@{ InstallerType = 'nullsoft' }) -Arguments '/s /ALLUSERS'
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/passthrough /S'
      $Fields.InstallerSwitches.SilentWithProgress | Should -Be '/passthrough /S'
      $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
      $Fields.InstallModes | Should -Not -Contain 'silentWithProgress'
    }
  }

  It 'uses Inno defaults without retaining a configured task selection' {
    $Metadata = New-DellSuggestionMetadata -Family 'Inno Setup' -Nested ([pscustomobject]@{ InstallerType = 'inno' }) -Arguments '/SILENT /TASKS="desktopicon,associate"'
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/passthrough /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
      $Fields.InstallerSwitches.SilentWithProgress | Should -Be '/passthrough /SP- /SILENT /SUPPRESSMSGBOXES /NORESTART'
      $Fields.InstallerSwitches.Log | Should -Be '/LOG="<LOGPATH>"'
      $Fields.InstallerSwitches.InstallLocation | Should -Be '/DIR="<INSTALLPATH>"'
      $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
    }
  }

  It 'uses suite switches without borrowing a hidden MSI directory property' {
    $Metadata = New-DellSuggestionMetadata -Family InstallShield -Nested ([pscustomobject]@{ InstallerType = 'exe'; Variant = 'Advanced UI'; InstallShieldProjectType = 'Advanced UI' }) -Arguments '/silent'
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/passthrough /silent'
      $Fields.InstallerSwitches.SilentWithProgress | Should -Be '/passthrough /passive'
      $Fields.InstallerSwitches.InstallLocation | Should -Be '/INSTALLDIR="<INSTALLPATH>"'
      $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
      $Fields.InstallerSwitches.Values -join ' ' | Should -Not -Match '/V'
    }
  }

  It 'does not parse invalid embedded InstallShield v operands into the preferred defaults' -ForEach @(
    @{ Arguments = '/s /v' }
    @{ Arguments = '/s /v /qn' }
    @{ Arguments = '/s /v "/qn TRANSFORMS=\"custom transform.mst\""' }
  ) {
    $Metadata = New-DellSuggestionMetadata -Family InstallShield -Nested ([pscustomobject]@{ InstallerType = 'msi' }) -Wrapper ([pscustomobject]@{ InstallerType = 'exe'; InstallShieldProjectType = 'Basic MSI' }) -Arguments $Arguments
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/passthrough /S /V/quiet /V/norestart'
      $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
    }
  }

  It 'keeps the embedded command for incomplete, interactive-only or indirectly selected nested routes' -ForEach @(
    @{ Route = 'Missing' }
    @{ Route = 'Unknown' }
    @{ Route = 'Interactive' }
    @{ Route = 'SFX' }
  ) {
    $Metadata = New-DellSuggestionMetadata -Family Squirrel -Nested ([pscustomobject]@{ InstallerType = 'exe' }) -Arguments '--silent'
    switch ($Route) {
      Missing { $Metadata.NestedInstallerInfo = $null }
      Unknown { $Metadata.NestedFamily = 'Custom launcher' }
      Interactive { $Metadata.NestedFamily = 'Setup Factory'; $Metadata.NestedInstallerInfo | Add-Member SupportsSilentInstallation $false }
      SFX { $Metadata.ExecutionChain = @([pscustomobject]@{ Family = '7z SFX' }) }
    }
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/s'
      $Fields.InstallerSwitches.Log | Should -Be '/l="<LOGPATH>"'
    }
  }

  It 'prefers family defaults even when the embedded command already matches them' {
    $Metadata = New-DellSuggestionMetadata -Family Squirrel -Nested ([pscustomobject]@{ InstallerType = 'exe' }) -Arguments '--silent'
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Result = Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })
      $Result.ManifestFields.InstallerSwitches.Silent | Should -Be '/passthrough --silent'
      $Result.ManifestVariants[0].Evidence.VendorArguments | Should -Be '--silent'
    }
  }

  It 'never carries embedded MSI UI tokens into family-default commands' -ForEach @(
    @{ Family = 'MSI'; Type = 'msi'; Arguments = '/qn+ ALLUSERS=1' }
    @{ Family = 'MSI'; Type = 'wix'; Arguments = '/qb- REINSTALL=all' }
    @{ Family = 'Advanced Installer'; Type = 'exe'; Arguments = '/exenoui /qn ALLUSERS=1' }
  ) {
    $Metadata = New-DellSuggestionMetadata -Family $Family -Nested ([pscustomobject]@{ InstallerType = $Type }) -Arguments $Arguments
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata; Arguments = $Arguments } {
      $Result = Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })
      $Result.ManifestFields.InstallerSwitches.Contains('Custom') | Should -BeFalse
      $Result.ManifestFields.InstallerSwitches.Silent | Should -Match '/quiet /norestart$'
      $Result.ManifestFields.InstallerSwitches.SilentWithProgress | Should -Match '/passive /norestart$'
      $Result.ManifestVariants[0].Evidence.VendorArguments | Should -BeExactly $Arguments
    }
  }

  It 'does not invent an unattended embedded alternative when MUP has none' {
    $Metadata = New-DellSuggestionMetadata -Family MSI -Nested ([pscustomobject]@{ InstallerType = 'msi' }) -Arguments '/qn <VALUE>'
    $Metadata.InstallerSwitches.Clear()
    $Metadata.InstallModes = @('interactive')
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Result = Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })
      $Result.ManifestFields.InstallerSwitches.Silent | Should -Be '/passthrough /quiet /norestart'
      $Result.ManifestVariants.Count | Should -Be 0
    }
  }

  It 'does not replace an explicitly supplied passthrough command' {
    $Metadata = New-DellSuggestionMetadata -Family MSI -Nested ([pscustomobject]@{ InstallerType = 'msi' })
    $Metadata.CommandBehavior.UsesPassthrough = $true
    $Metadata.InstallerSwitches.Clear()
    $Metadata.InstallModes = @()
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Metadata } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.PSObject.Properties.Name | Should -Not -Contain 'InstallerSwitches'
      $Fields.PSObject.Properties.Name | Should -Not -Contain 'InstallModes'
    }
  }

  It 'returns independent WinGet default dictionaries without changing validation state' {
    $Switches = Get-WinGetInstallerDefaultSwitches -InstallerType msi
    $Switches.Silent = 'changed'
    (Get-WinGetInstallerDefaultSwitches -InstallerType msi).Silent | Should -Be '/quiet /norestart'
    (Get-WinGetInstallerDefaultSwitches -InstallerType exe).Count | Should -Be 0
    (Get-WinGetInstallerDefaultSwitches -InstallerType '').Count | Should -Be 0
  }
}

Describe 'Dell real media regressions' -Tag Integration {
  It 'reads historical framework 3.0 ZIP/MUP 2.1 media <ReleaseID>' -ForEach @(
    @{ ReleaseID = 'CPNKY'; Version = '9.3.0.1019'; Selected = 'setup.exe' }
    @{ ReleaseID = 'NN71R'; Version = '8.1.0'; Selected = 'omcix64.msi' }
    @{ ReleaseID = 'GVCVP'; Version = '15.7.0.0'; Selected = 'setup.exe' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath "Installers\DellUpdatePackage\Catalog.$ReleaseID\$Version\setup.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Historical Dell catalog fixture is not cached.'; return }
    $Info = Get-DellUpdatePackageInfo -Path $Path
    $Info.ContainerRoute | Should -Be 'Zip'
    $Info.FrameworkVersion | Should -Be '003.000.000.000'
    $Info.Configuration.SpecificationVersion | Should -Be '2.1.0'
    $Info.Configuration.ExecutableName | Should -Be $Selected
    if ($ReleaseID -ceq 'NN71R') {
      $Info.NestedFamily | Should -Be 'MSI'
      $Info.ProductCode | Should -Be '{D390C5DD-9312-4F70-B3B1-4EAE635CDA17}'
      $Info.DisplayName | Should -Be 'Dell OpenManage Client Instrumentation'
    } else {
      # Vendor launchers are not replaced by a guessed MSI or an inventory ID.
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.Nested.Incomplete'
    }
  }

  It 'does not misclassify legacy SVMSEZ32 or BIOS media as DUPFramework' -ForEach @(
    @{ ReleaseID = 'X2XJJ'; Version = '265.70' }
    @{ ReleaseID = 'K0T3Y'; Version = 'A08' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath "Installers\DellUpdatePackage\Catalog.$ReleaseID\$Version\setup.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Dell alternative-container fixture is not cached.'; return }
    Test-DellUpdatePackage -Path $Path | Should -BeFalse
    { Get-DellUpdatePackageInfo -Path $Path } | Should -Throw '*DUP framework*'
  }

  It 'parses <Package> <Version> and resolves the configured InstallShield identity' -ForEach @(
    @{ Package = 'Dell.CommandUpdate'; Version = '4.1.0'; Route = 'Zip'; Architecture = 'x86'; ProductCode = '{4CD85DD3-A024-4409-A0F2-F70DE1E4A935}' }
    @{ Package = 'Dell.CommandUpdate'; Version = '5.7.2'; Route = 'SevenZip'; Architecture = 'x86'; ProductCode = '{F3C8A91E-7B42-4D6F-8E25-C9A7B14D5E30}' }
    @{ Package = 'Dell.CommandUpdate.Universal'; Version = '5.7.2'; Route = 'SevenZip'; Architecture = 'x64'; ProductCode = '{8F2D7A4C-B9E1-4C63-A5F8-D2E7B91C4A6F}' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath "Installers\DellUpdatePackage\$Package\$Version\setup.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Dell persistent fixture is not cached.'; return }
    $Info = Get-DellUpdatePackageInfo -Path $Path
    $Info.ContainerRoute | Should -Be $Route
    $Info.ProductVersion | Should -Be $Version
    $Info.ProductCode | Should -Be $ProductCode
    $Info.Scope | Should -Be 'machine'
    $Info.NestedFamily | Should -Be 'InstallShield'
    $Info.NestedPackageArchitecture | Should -Be $Architecture
    $Info.Configuration.InventoryUpgradeCodes | Should -Contain $Info.UpgradeCode
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '/s'
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be $ProductCode
  }

  It 'retains driver inventory without inventing an uninstall ProductCode' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\DellUpdatePackage\Dell.WatchdogTimer\2.0.0.1\setup.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Dell driver fixture is not cached.'; return }
    $Info = Get-DellUpdatePackageInfo -Path $Path
    $Info.Configuration.Inventory -join '' | Should -Match 'ManageableUpdatePackage'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Contain 'DellUpdatePackage.ARP.Unresolved'
    $Info.UnresolvedFields | Should -Contain 'AppsAndFeaturesEntries'
    $Info.ExecutionChain.Count | Should -Be 1
    $Info.ExecutionChain[0].SelectedPayload | Should -Be 'WDTAppSetUp.exe'
    $Info.ExecutionChain[0].Arguments | Should -Be '/s'
    InModuleScope WinGetAnalysis -Parameters @{ Metadata = $Info } {
      $Fields = (Get-WinGetParserResultSuggestion -Result ([pscustomobject]@{ Family = 'Dell Update Package'; InstallerType = 'exe'; Metadata = $Metadata })).ManifestFields
      $Fields.InstallerSwitches.Silent | Should -Be '/s'
      $Fields.InstallerSwitches.SilentWithProgress | Should -Be '/s'
      $Fields.InstallerSwitches.Log | Should -Be '/l="<LOGPATH>"'
      $Fields.InstallerSwitches.Values -join ' ' | Should -Not -Match '/passthrough'
    }
  }

  It 'uses the ARM64 Optimizer suite identity instead of any of its nested MSI identities' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\DellUpdatePackage\Dell.Optimizer\6.3.5.0-arm64\setup.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Dell suite fixture is not cached.'; return }
    $Info = Get-DellUpdatePackageInfo -Path $Path
    $Info.ProductCode | Should -Be '{CC40119D-6ADF-4832-8025-4808195E41D5}'
    $Info.DisplayName | Should -Be 'Dell Optimizer'
    $Info.DisplayVersion | Should -Be '6.3.5.0'
    $Info.Publisher | Should -Be 'Dell Technologies Inc.'
    $Info.NestedInstallerInfo.Variant | Should -Be 'Advanced UI'
    $Info.AppsAndFeaturesEntries[0].InstallerType | Should -Be 'exe'
    $Info.PackageArchitecture | Should -Be 'arm64'
    $Info.Diagnostics.Id | Should -Not -Contain 'DellUpdatePackage.Nested.Incomplete'
  }

  It 'routes the outer wrapper, projects valid WinGet fields and refreshes existing identity' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\DellUpdatePackage\Dell.CommandUpdate\5.7.2\setup.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Dell fixture is not cached.'; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Path
    $Analysis.DetectedFamilies.Family | Should -Contain 'Dell Update Package'
    $Analysis.ParserResults | Where-Object Success | Measure-Object | Select-Object -ExpandProperty Count | Should -Be 1
    $Result = $Analysis.ParserResults | Where-Object Name -EQ 'Dell Update Package'
    $Fields = $Result.Result.SuggestedManifestFields
    $Fields.InstallerType | Should -Be 'exe'
    $Fields.ProductCode | Should -Be '{F3C8A91E-7B42-4D6F-8E25-C9A7B14D5E30}'
    $Fields.InstallerSwitches.Silent | Should -Match '^/passthrough /S /V/quiet'
    $Fields.ExpectedReturnCodes.InstallerReturnCode | Should -Contain 2
    $Fields.ExpectedReturnCodes.InstallerReturnCode | Should -Not -Contain 3010
    $Fields.InstallerSwitches.Contains('Custom') | Should -BeFalse
    $Alternative = @($Analysis.SuggestedManifestVariants | Where-Object Name -EQ EmbeddedMup)[0]
    $Alternative.ManifestFields.InstallerSwitches.Silent | Should -Be '/s'
    $Alternative.Evidence.VendorArguments | Should -BeExactly $Result.Result.Metadata.CommandBehavior.DefaultVendorArguments
    $Result.Result.SuggestedManifestVariants[0].Name | Should -Be 'EmbeddedMup'
    InModuleScope WinGetAnalysis -Parameters @{ Fields = $Fields } {
      $Schema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion '1.12.0'
      $Entry = Merge-WinGetManifestDictionary -Base ([ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64 }) -Override (ConvertTo-WinGetSuggestedManifestFieldSet -InputObject $Fields)
      (Get-YamlSchemaValidationResult -InputObject $Entry -Schema $Schema.definitions.Installer -RootSchema $Schema -ValidatePropertyNames).IsValid | Should -BeTrue
    }
    InModuleScope WinGetManifestUpdate -Parameters @{ Path = $Path; Analysis = $Analysis } {
      $Info = Get-WinGetGenericInstallerManifestInfo -Path $Path -Analysis $Analysis -Architecture x64 -Logger { }
      $Info.ParserName | Should -Be 'Dell Update Package'
      $Info.InputObject[0].ProductCode | Should -Be '{F3C8A91E-7B42-4D6F-8E25-C9A7B14D5E30}'
    }
  }

  It 'routes a real passthrough override without suggesting default wrapper switches' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\DellUpdatePackage\Dell.CommandUpdate\4.1.0\setup.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Dell fixture is not cached.'; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Path -CommandLine ('"' + $Path + '" /passthrough /s /v"/qn ARPSYSTEMCOMPONENT=1"')
    $Parser = $Analysis.ParserResults | Where-Object Name -EQ 'Dell Update Package'
    $Parser.Success | Should -BeTrue
    $Parser.Result.Metadata.CommandBehavior.UsesPassthrough | Should -BeTrue
    $Parser.Result.Metadata.ProductCode | Should -BeNullOrEmpty
    $Parser.Result.SuggestedManifestFields.Keys | Should -Not -Contain 'InstallerSwitches'
    $Parser.Result.SuggestedManifestFields.Keys | Should -Not -Contain 'InstallModes'
  }
}
