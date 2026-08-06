BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Cabinet.psm1') -Force
  . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Installers' 'MSI.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Installers' 'InstallShield.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Installers' 'InstallShieldInstallScript.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallShield'
  $Script:MsiFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\MSI'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [string]$Sha256
    )

    $Arguments = @{ Directory = $Script:FixtureDirectory; Name = $Name; Uri = $Url }
    if ($Sha256) { $Arguments.Sha256 = $Sha256 }
    Get-DumplingsTestFixture @Arguments
  }

  function New-TestInstallShieldSpannedCabinet {
    param ([Parameter(Mandatory)][string]$Path)

    $Payload = [Text.Encoding]::UTF8.GetBytes(('Dumplings split InstallShield cabinet payload. ' * 256))
    $CompressedStream = [IO.MemoryStream]::new()
    try {
      $Deflater = [IO.Compression.DeflateStream]::new($CompressedStream, [IO.Compression.CompressionLevel]::Optimal, $true)
      try { $Deflater.Write($Payload, 0, $Payload.Length) } finally { $Deflater.Dispose() }
      $Compressed = $CompressedStream.ToArray()
    } finally {
      $CompressedStream.Dispose()
    }
    if ($Compressed.Length -gt [uint16]::MaxValue) { throw 'The synthetic InstallShield compressed block is too large.' }
    $Stored = [byte[]]::new($Compressed.Length + 2)
    [BitConverter]::GetBytes([uint16]$Compressed.Length).CopyTo($Stored, 0)
    $Compressed.CopyTo($Stored, 2)

    $Directory = Split-Path -Path $Path -Parent
    $DescriptorBase = 0x20
    $TableOffset = 0x100
    $TableBase = $DescriptorBase + $TableOffset
    $DescriptorTableOffset = 0x100
    $RecordSize = 0x57
    $Header = [byte[]]::new(0x500)
    $WriteUInt16 = { param([byte[]]$Bytes, [int]$Offset, [uint16]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt32 = { param([byte[]]$Bytes, [int]$Offset, [uint32]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt64 = { param([byte[]]$Bytes, [int]$Offset, [uint64]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteString = {
      param([byte[]]$Bytes, [int]$Offset, [string]$Value)
      [Text.Encoding]::Unicode.GetBytes($Value + [char]0).CopyTo($Bytes, $Offset)
    }

    # data1.hdr contains one compressed split descriptor and one linked alias.
    & $WriteUInt32 $Header 0 ([uint32]0x28635349)
    & $WriteUInt32 $Header 4 ([uint32]0x04000C80)
    & $WriteUInt32 $Header 12 ([uint32]$DescriptorBase)
    & $WriteUInt32 $Header 16 ([uint32]($Header.Length - $DescriptorBase))
    & $WriteUInt32 $Header ($DescriptorBase + 0x0C) ([uint32]$TableOffset)
    & $WriteUInt32 $Header ($DescriptorBase + 0x14) ([uint32]0x1C0)
    & $WriteUInt32 $Header ($DescriptorBase + 0x18) ([uint32]0x1C0)
    & $WriteUInt32 $Header ($DescriptorBase + 0x1C) ([uint32]1)
    & $WriteUInt32 $Header ($DescriptorBase + 0x28) ([uint32]2)
    & $WriteUInt32 $Header ($DescriptorBase + 0x2C) ([uint32]$DescriptorTableOffset)
    & $WriteUInt32 $Header $TableBase ([uint32]0x10)
    & $WriteString $Header ($TableBase + 0x10) 'payload'
    & $WriteString $Header ($TableBase + 0x30) 'split.bin'
    & $WriteString $Header ($TableBase + 0x60) 'alias.bin'

    $Digest = [Security.Cryptography.MD5]::HashData($Payload)
    foreach ($Record in @(
        @{ Index = 0; NameOffset = 0x30; Flags = 5; LinkPrevious = 0; LinkFlags = 0 }
        @{ Index = 1; NameOffset = 0x60; Flags = 4; LinkPrevious = 0; LinkFlags = 1 }
      )) {
      $Offset = $TableBase + $DescriptorTableOffset + $Record.Index * $RecordSize
      & $WriteUInt16 $Header $Offset ([uint16]$Record.Flags)
      & $WriteUInt64 $Header ($Offset + 2) ([uint64]$Payload.Length)
      & $WriteUInt64 $Header ($Offset + 10) ([uint64]$Stored.Length)
      & $WriteUInt64 $Header ($Offset + 18) ([uint64]84)
      $Digest.CopyTo($Header, $Offset + 26)
      & $WriteUInt32 $Header ($Offset + 58) ([uint32]$Record.NameOffset)
      & $WriteUInt16 $Header ($Offset + 62) ([uint16]0)
      & $WriteUInt32 $Header ($Offset + 76) ([uint32]$Record.LinkPrevious)
      $Header[$Offset + 84] = [byte]$Record.LinkFlags
      & $WriteUInt16 $Header ($Offset + 85) ([uint16]1)
    }
    [IO.File]::WriteAllBytes($Path, $Header)

    # Split the stored Deflate frame after its first length byte. This proves
    # the logical stream, rather than the decompressor, owns volume traversal.
    $SplitAt = 1
    foreach ($Volume in 1, 2) {
      $Start = $Volume -eq 1 ? 0 : $SplitAt
      $Count = $Volume -eq 1 ? $SplitAt : $Stored.Length - $SplitAt
      $Cabinet = [byte[]]::new(84 + $Count)
      & $WriteUInt32 $Cabinet 0 ([uint32]0x28635349)
      & $WriteUInt32 $Cabinet 4 ([uint32]0x04000C80)
      & $WriteUInt32 $Cabinet 28 ([uint32]0)
      & $WriteUInt32 $Cabinet 32 ([uint32]0)
      foreach ($Offset in 36, 60) { & $WriteUInt64 $Cabinet $Offset ([uint64]84) }
      foreach ($Offset in 44, 68) { & $WriteUInt64 $Cabinet $Offset ([uint64]$Payload.Length) }
      foreach ($Offset in 52, 76) { & $WriteUInt64 $Cabinet $Offset ([uint64]$Count) }
      [Array]::Copy($Stored, $Start, $Cabinet, 84, $Count)
      [IO.File]::WriteAllBytes((Join-Path $Directory "data$Volume.cab"), $Cabinet)
    }

    return [pscustomobject]@{ Payload = $Payload; StoredLength = $Stored.Length }
  }
}

Describe 'InstallShield parser' {
  It 'streams compressed split entries across volumes and resolves linked aliases' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $Fixture = New-TestInstallShieldSpannedCabinet -Path $HeaderPath
    $Destination = Join-Path $TestDrive 'spanned-expanded'

    $Result = Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath $Destination -CollisionAction Error

    $Result | Should -Be (Get-Item -LiteralPath $Destination).FullName
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\split.bin')) | Should -Be $Fixture.Payload
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\alias.bin')) | Should -Be $Fixture.Payload
  }

  It 'rejects cyclic InstallShield cabinet link chains before opening payload volumes' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $null = New-TestInstallShieldSpannedCabinet -Path $HeaderPath
    $Header = [IO.File]::ReadAllBytes($HeaderPath)
    $FirstDescriptor = 0x20 + 0x100 + 0x100
    [BitConverter]::GetBytes([uint32]1).CopyTo($Header, $FirstDescriptor + 76)
    $Header[$FirstDescriptor + 84] = 1
    [IO.File]::WriteAllBytes($HeaderPath, $Header)

    { Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath (Join-Path $TestDrive 'cycle') -Name 'split.bin' -CollisionAction Error } |
      Should -Throw '*link chain contains a cycle*'
  }

  It 'builds one analysis context with one extraction, tree walk, and nested MSI parse' {
    $Fixture = Join-Path $TestDrive 'context-setup.exe'
    $Destination = Join-Path $TestDrive 'context-expanded'
    $MsiPath = Join-Path $Destination 'selected.msi'
    [IO.File]::WriteAllBytes($Fixture, [byte[]](0x4D, 0x5A, 0, 0))
    $null = New-Item -Path $Destination -ItemType Directory -Force
    [IO.File]::WriteAllBytes($MsiPath, [byte[]](0))

    InModuleScope InstallShield -Parameters @{ Fixture = $Fixture; Destination = $Destination; MsiPath = $MsiPath } {
      param($Fixture, $Destination, $MsiPath)
      Mock Get-PEOverlayOffset { 0 }
      Mock Invoke-InstallShieldExtraction { [pscustomobject]@{ Result = $Destination; Files = @() } }
      Mock Expand-InstallShieldCabinetSupport { [pscustomobject]@{ ExtractedFiles = @(); Warnings = @() } }
      Mock Get-ChildItem { @(Get-Item -LiteralPath $MsiPath) }
      Mock Get-InstallShieldMsiPayloadSelection {
        [pscustomobject]@{ Configuration = $null; SelectedMsiPath = $MsiPath; SelectionSource = 'Test'; Warnings = @() }
      }
      Mock Resolve-InstallShieldMsiFile { Get-Item -LiteralPath $MsiPath }
      Mock Get-MsiInstallerInfo { [pscustomobject]@{ InstallShieldProjectType = 'Basic MSI' } }

      $Context = New-InstallShieldAnalysisContext -Path $Fixture -DestinationPath $Destination

      $Context.Variant | Should -Be 'Basic MSI'
      Should -Invoke Invoke-InstallShieldExtraction -Exactly 1
      Should -Invoke Expand-InstallShieldCabinetSupport -Exactly 1
      Should -Invoke Get-ChildItem -Exactly 1
      Should -Invoke Get-InstallShieldMsiPayloadSelection -Exactly 1
      Should -Invoke Get-MsiInstallerInfo -Exactly 1
    }
  }

  It 'Should parse Advanced UI SuiteId and its exact nested package catalog' {
    $Fixture = Join-Path $Script:FixtureDirectory 'AdvancedUI\SketchUpViewer-2022-0-316-108.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent SketchUp Viewer Advanced UI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.Variant | Should -Be 'Advanced UI'
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
      $Info.LimitedUserCompatible | Should -BeFalse
      $Info.RequiresAdministrativePrivileges | Should -BeTrue
      $Info.HasSilentCommandLine | Should -BeTrue
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
    $PrerequisiteFixtureDirectory = Join-Path $Script:FixtureDirectory 'PrerequisiteElevation'
    $Fixture = Get-DumplingsTestFixture `
      -Directory $PrerequisiteFixtureDirectory `
      -Name 'AFAS.ProfitCommunicationCenter.7.exe' `
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
    $PrerequisiteFixtureDirectory = Join-Path $Script:FixtureDirectory 'PrerequisiteElevation'
    $Fixture = Get-DumplingsTestFixture `
      -Directory $PrerequisiteFixtureDirectory `
      -Name 'Vertexshare.WebpConverter.exe' `
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

  It 'Should identify an official builder-generated InstallScript MSI project' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderDifferential\InstallScriptMSI\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official InstallShield builder fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'InstallScript MSI'
      $Info.InstallShieldProjectTypeEvidence.CustomActions | Should -Contain 'ISVerifyScriptingRuntime'
      $Info.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $Info.HasInstallScript | Should -BeFalse
      $MsiInfo.InstallShieldProjectType | Should -Be 'InstallScript MSI'
      $MsiInfo.DisplayName | Should -Be 'Dumplings InstallScript MSI'
      $MsiInfo.DisplayVersion | Should -Be '1.2.3'
      $MsiInfo.InstallShieldScriptActions.Action | Should -Contain 'ISVerifyScriptingRuntime'
      $MsiInfo.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $MsiInfo.InstallShieldLauncherRequirement.SequenceConditions | Should -Contain 'NOT AFTERREBOOT AND NOT ISSETUPDRIVEN'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'ISVerifyScriptingRuntime').Sequences.Count | Should -BeGreaterThan 0
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should retain InstallScript MSI classification while analyzing its compiled action' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderDifferential\InstallScriptMSIWithAction\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official scripted InstallScript MSI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = $Info.SelectedMsiInfo

      $Info.Variant | Should -Be 'InstallScript MSI'
      $Info.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $MsiInfo.InstallShieldScriptInfo.EntryPoints | Should -Be 'CreateCboContents'
      $MsiInfo.InstallShieldScriptInfo.Analysis.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Function | Should -Be 'CreateCboContents'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'ISVerifyScriptingRuntime').Kind | Should -Be 'RuntimeVerifier'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover official Basic MSI InstallScript custom actions from Binary.ISSetup.dll' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderDifferential\InstallScriptMSIScripted\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official scripted Basic MSI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = $Info.SelectedMsiInfo

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldProjectType | Should -Be 'Basic MSI'
      $MsiInfo.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldScriptInfo.BinaryName | Should -Be 'ISSetup.dll'
      $MsiInfo.InstallShieldScriptInfo.EntryPoints | Should -Be @(
        'CreateCboContents', 'DllWrapper', 'QueryRegistry', 'ShowRegTestProperty'
      )
      $MsiInfo.InstallShieldScriptInfo.Analysis.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Target | Should -Be 'f1'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Function | Should -Be 'CreateCboContents'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should not misclassify Basic MSI media merely because it carries setup.inx' {
    $Fixture = Join-Path $Script:FixtureDirectory 'PenSoftware_v3_9_2_2_jp_Setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent SHARP Pen Software fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.HasInstallScript | Should -BeTrue
      $Info.Variant | Should -Be 'Basic MSI'
      $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
      $Info.InstallScriptInfo | Should -Not -BeNullOrEmpty
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should retain the legacy extraction command without depending on ISx.exe' {
    Get-ChildItem (Join-Path $PSScriptRoot '..' 'Assets') -Filter 'ISx.exe' -File -Recurse |
      Should -BeNullOrEmpty

    InModuleScope InstallShield {
      Mock Expand-InstallShieldInstaller { 'C:\Extracted\Setup_u' }

      Expand-InstallShield -Path 'C:\Fixtures\Setup.exe' -CollisionAction Rename | Should -Be 'C:\Extracted\Setup_u'
      Should -Invoke Expand-InstallShieldInstaller -Exactly 1 -ParameterFilter {
        $Path -eq 'C:\Fixtures\Setup.exe' -and [string]::IsNullOrEmpty($DestinationPath) -and
        $MaximumExpandedBytes -eq 8GB
      }
    }
  }

  It 'Should distinguish type 3 ISSetupStream attributes with and without timestamps' {
    InModuleScope InstallShield {
      $NameBytes = [Text.Encoding]::Unicode.GetBytes("Setup.inx$([char]0)")
      $Payload = [byte[]](1, 2, 3, 4)
      $Record = [byte[]]::new(24 + 24 + $NameBytes.Length + $Payload.Length)
      [BitConverter]::GetBytes([uint32]$NameBytes.Length).CopyTo($Record, 0)
      [BitConverter]::GetBytes([uint32]6).CopyTo($Record, 4)
      [BitConverter]::GetBytes([uint32]$Payload.Length).CopyTo($Record, 10)
      [BitConverter]::GetBytes([uint16]1).CopyTo($Record, 22)
      for ($Index = 0; $Index -lt 3; $Index++) {
        [BitConverter]::GetBytes(([datetime]'2026-01-02T03:04:05Z').ToFileTimeUtc()).CopyTo($Record, 24 + $Index * 8)
      }
      $NameBytes.CopyTo($Record, 48)
      $Payload.CopyTo($Record, 48 + $NameBytes.Length)

      $Stream = [IO.MemoryStream]::new($Record)
      try {
        $Attribute = Get-InstallShieldStreamAttribute -Stream $Stream -Offset 0 -Type 3

        $Attribute.FileName | Should -Be 'Setup.inx'
        $Attribute.FileLength | Should -Be $Payload.Length
        $Attribute.DataOffset | Should -Be (48 + $NameBytes.Length)
      } finally {
        $Stream.Dispose()
      }

      $RecordWithoutTimestamps = [byte[]]::new(24 + $NameBytes.Length + $Payload.Length)
      [BitConverter]::GetBytes([uint32]$NameBytes.Length).CopyTo($RecordWithoutTimestamps, 0)
      [BitConverter]::GetBytes([uint32]6).CopyTo($RecordWithoutTimestamps, 4)
      [BitConverter]::GetBytes([uint32]$Payload.Length).CopyTo($RecordWithoutTimestamps, 10)
      [BitConverter]::GetBytes([uint16]1).CopyTo($RecordWithoutTimestamps, 22)
      $NameBytes.CopyTo($RecordWithoutTimestamps, 24)
      $Payload.CopyTo($RecordWithoutTimestamps, 24 + $NameBytes.Length)
      $Stream = [IO.MemoryStream]::new($RecordWithoutTimestamps)
      try {
        $Attribute = Get-InstallShieldStreamAttribute -Stream $Stream -Offset 0 -Type 3
        $Attribute.FileName | Should -Be 'Setup.inx'
        $Attribute.DataOffset | Should -Be (24 + $NameBytes.Length)
      } finally {
        $Stream.Dispose()
      }
    }
  }

  It 'Should stream an encoded zlib payload without whole-buffer parser reads' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-streaming'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    $FileName = 'LargePayload.msi'
    $Seed = [Text.Encoding]::UTF8.GetBytes($FileName)
    $Magic = [byte[]](0x13, 0x35, 0x86, 0x07)
    $Expected = [Text.Encoding]::UTF8.GetBytes(('InstallShield streaming regression payload.' * 4096))
    $CompressedStream = [IO.MemoryStream]::new()
    $Compressor = [IO.Compression.ZLibStream]::new($CompressedStream, [IO.Compression.CompressionLevel]::Optimal, $true)
    try {
      $Compressor.Write($Expected, 0, $Expected.Length)
    } finally {
      $Compressor.Dispose()
    }
    $Compressed = $CompressedStream.ToArray()
    $CompressedStream.Dispose()

    $Key = [byte[]]::new($Seed.Length)
    for ($Index = 0; $Index -lt $Seed.Length; $Index++) { $Key[$Index] = $Seed[$Index] -bxor $Magic[$Index % $Magic.Length] }
    $Encoded = [byte[]]::new($Compressed.Length)
    for ($Index = 0; $Index -lt $Compressed.Length; $Index++) {
      $Mixed = ((-bnot $Compressed[$Index]) -band 0xFF) -bxor $Key[($Index % 1024) % $Key.Length]
      $Encoded[$Index] = (($Mixed -shl 4) -bor ($Mixed -shr 4)) -band 0xFF
    }

    try {
      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath; FileName = $FileName; Seed = $Seed; Encoded = $Encoded; Expected = $Expected } {
        $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
        $Stream = [IO.MemoryStream]::new($Encoded)
        try {
          $Attribute = [pscustomobject]@{
            FileName          = $FileName
            Seed              = $Seed
            EncodedFlags      = 6
            FileLength        = $Encoded.Length
            IsUnicodeLauncher = 1
            DataOffset        = 0
          }
          # The record decoder must honor the operation's remaining budget and
          # remove its partial output before a caller retries with a larger one.
          { Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $ExpandedPath `
              -MaximumBytes ($Expected.Length - 1) -StreamMode } | Should -Throw '*limit*'
          Test-Path -LiteralPath (Join-Path $ExpandedPath $FileName) | Should -BeFalse
          $Stream.Position = 0
          $OutputPath = Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $ExpandedPath -StreamMode
          Test-BinarySequence -Left ([IO.File]::ReadAllBytes($OutputPath)) -Right $Expected | Should -BeTrue
        } finally {
          $Stream.Dispose()
        }
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover compiled InstallScript actions from the Tenable Nessus MSI' {
    $Fixture = Join-Path $Script:MsiFixtureDirectory 'Nessus-10.12.3-x64.msi'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent Tenable Nessus MSI fixture is unavailable.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
    $Info.InstallShieldScriptInfo.HasCompiledScript | Should -BeTrue
    $Info.InstallShieldScriptInfo.EntryPoints | Should -Contain 'CheckDirPathPermissions'
    $Info.InstallShieldScriptInfo.EntryPoints | Should -Contain 'SetupProperties'
    $Info.InstallShieldScriptInfo.ExtractedFiles | Should -Contain 'Setup.inx'
    $Info.InstallShieldScriptInfo.ExtractedFiles | Should -Contain 'IsConfig.ini'
    $Info.InstallShieldScriptInfo.Analysis | Should -Not -BeNullOrEmpty
    $Info.Warnings | Should -Not -Match 'Embedded InstallScript custom-action analysis failed'
  }

  It 'Should expose the PackageForTheWeb launch chain without executing it' {
    $Fixture = Join-Path $Script:FixtureDirectory 'U90Ladder_6_6_45.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent U90 Ladder PackageForTheWeb fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.ContainerFormat | Should -Be 'PackageForTheWeb Cabinet'
      $Info.PackageForTheWebInfo.Product | Should -Be 'U90Ladder'
      $Info.PackageForTheWebInfo.NestedSetupPath | Should -Be 'Setup.exe'
      $Info.PackageForTheWebInfo.NestedPayloadPath | Should -Be 'setup.inx'
      $Info.PackageForTheWebInfo.NestedPayloadKind | Should -Be 'InstallScript program'
      $Info.PackageForTheWebInfo.LaunchChain.Stage | Should -Be @('PackageForTheWeb', 'InstallShield setup launcher')
      $Info.PackageForTheWebInfo.LaunchChain[0].Arguments | Should -BeNullOrEmpty
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the AntRad installer' {
    $Fixture = Get-InstallerFixture -Name 'antrad_setup.exe' -Url 'https://pathloss.com/antrad_setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'antrad-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.SetupIniPath | Should -Be 'Setup.ini'
      $Info.MsiPayloadSelection.SelectionMethod | Should -Be 'SetupIni'
      $Info.MsiPayloadSelection.PackageName | Should -Be 'AntRad.msi'
      $Info.SelectedMsiPath | Should -Be 'AntRad.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'AntRad.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'AntRad'
      $MsiInfo.DisplayVersion | Should -Be '5.01.05'
      $MsiInfo.ProductCode | Should -Be '{9F6A3279-53F2-47C4-8FC8-3149620498EA}'
      $MsiInfo.UpgradeCode | Should -Be '{6767F0A3-5CD9-4B6F-90C4-693DADF557D8}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract the large AVer MSI with bounded memory' -Skip:($env:DUMPLINGS_RUN_LARGE_INSTALLER_TESTS -ne '1') {
    $Archive = Get-InstallerFixture -Name 'AVerTouch.zip' -Url 'https://download.aver.com/AVerTouchWindows/check4Update/AVerTouch.zip' -Sha256 '7E448DF1F753ED22C39DC8F840881622B6CFB294CDB071138D911481F19C51EC'
    $Fixture = Join-Path $Script:FixtureDirectory 'AVerTouchQt.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'aver-touch-expanded'
    $FixtureHash = '2D9C3D01E3284893DA78BF3FD633E699BD71747959B2F37253645D3C9D97252C'

    if (-not (Test-Path -LiteralPath $Fixture) -or (Get-DumplingsTestFixtureHash -Path $Fixture) -ne $FixtureHash) {
      $Zip = [IO.Compression.ZipFile]::OpenRead($Archive)
      try {
        $Entry = $Zip.GetEntry('AVerTouchQt.exe')
        if (-not $Entry) { throw 'The AVer archive does not contain AVerTouchQt.exe.' }
        $InputStream = $Entry.Open()
        $OutputStream = [IO.File]::Create($Fixture)
        try { $InputStream.CopyTo($OutputStream) } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
      } finally {
        $Zip.Dispose()
      }
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be $FixtureHash

    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.SelectedMsiPath | Should -Be 'AVerTouch.msi'
      (Get-Item -LiteralPath $MsiInfo.Path).Length | Should -Be 435532288
      $MsiInfo.PackageArchitecture | Should -Be 'x86'
      $MsiInfo.DisplayVersion | Should -Be '1.3.2114.0'
      $MsiInfo.ProductCode | Should -Be '{B16D6CCE-CC0A-4516-8BA8-897E24376A2B}'
      $MsiInfo.UpgradeCode | Should -Be '{2525391D-961E-42A8-B163-22226CAFB2CB}'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the Tachograph File Viewer installer' {
    $Fixture = Get-InstallerFixture -Name 'TachoFileViewer_3_40.exe' -Url 'https://www.prosysdev.com/downloads/TachoFileViewer_3_40.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'tachograph-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.PackageName | Should -Be 'Tachograph File Viewer.msi'
      $Info.SelectedMsiPath | Should -Be 'Tachograph File Viewer.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'Tachograph File Viewer.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'Tachograph File Viewer'
      $MsiInfo.DisplayVersion | Should -Be '3.40'
      $MsiInfo.ProductCode | Should -Be '{AAA4DC80-8FA6-4A8E-AFD2-D82B9CCCA2A8}'
      $MsiInfo.UpgradeCode | Should -Be '{F97E4ADC-C4FE-4253-B342-EC2D8873E27B}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the WiFi Sensor Software installer' {
    $Fixture = Get-InstallerFixture -Name 'WiFi Sensor Software.exe' -Url 'https://s3.amazonaws.com/easylogcloud/WiFi%20Sensor%20Software.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'wifi-sensor-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.PackageName | Should -Be 'WiFi Sensor Software.msi'
      $Info.SelectedMsiPath | Should -Be 'WiFi Sensor Software.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'WiFi Sensor Software.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'WiFi Sensor Software'
      $MsiInfo.DisplayVersion | Should -Be '1.40.15'
      $MsiInfo.ProductCode | Should -Be '{EF49368B-13B1-4F5B-B453-83C725D31F82}'
      $MsiInfo.UpgradeCode | Should -Be '{60BF28CD-D862-47B9-A3C1-A361DB53CF77}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should select the Setup.ini MSI instead of the first wildcard match' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-selection'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $null = New-Item -Path (Join-Path $ExpandedPath 'payload') -ItemType Directory -Force
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'First.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'payload\Selected.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllText((Join-Path $ExpandedPath 'Setup.ini'), @'
[Startup]
PackageName=Selected.msi

[Selected.msi]
Type=1
Location=payload\Selected.msi
'@)

      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath } {
        $MsiFiles = @(Get-ChildItem -LiteralPath $ExpandedPath -Filter '*.msi' -Recurse -File)
        $Selection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExpandedPath -MsiFile $MsiFiles
        $Installer = [pscustomobject]@{
          ExtractedPath       = $ExpandedPath
          MsiPayloadSelection = $Selection
        }
        $Selected = Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false

        $Selection.SelectionMethod | Should -Be 'SetupIni'
        $Selection.SelectedMsiPath | Should -Be 'payload\Selected.msi'
        $Selected.Name | Should -Be 'Selected.msi'
        { Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern 'First.msi' -NameWasSpecified $true } | Should -Throw '*does not match the requested pattern*'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should follow an InstallShield 11.5 external-media Setup.ini without scanning sibling files' {
    $FixtureRoot = Join-Path $Script:FixtureDirectory 'BuilderDifferential\Legacy115\BuilderInstaller'
    $Fixture = Join-Path $FixtureRoot 'setup.exe'
    $MsiFixture = Join-Path $FixtureRoot 'InstallShield1150.msi'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf) -or
      -not (Test-Path -LiteralPath $MsiFixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 11.5 external-media fixture is unavailable.'
      return
    }

    $ExpandedPath = Join-Path $Script:FixtureDirectory 'installshield-115-external-expanded'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.SourceKind | Should -Be 'ExternalSibling'
      $Info.SetupIniPath | Should -Be 'Setup.ini'
      $Info.SelectedMsiPath | Should -Be 'InstallShield1150.msi'
      $Info.MsiFiles | Should -Contain (Get-Item -LiteralPath $MsiFixture).FullName
      $MsiInfo.Path | Should -Be (Get-Item -LiteralPath $MsiFixture).FullName
      $MsiInfo.DisplayName | Should -Be 'InstallShield 11.5'
      $MsiInfo.DisplayVersion | Should -Be '11.50.0000'
      $MsiInfo.ProductCode | Should -Be '{97033B64-7CE1-428F-BD7F-101D26C9AF9E}'
      $MsiInfo.UpgradeCode | Should -Be '{474F074C-7A6F-45A7-9550-8D5ECE5938DE}'
      $MsiInfo.InstallShieldProjectType | Should -Be 'Basic MSI'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should not substitute an unrelated sibling MSI for a missing Setup.ini package' {
    $MediaRoot = Join-Path $TestDrive 'external-media-missing-package'
    $ExpandedPath = Join-Path $TestDrive 'external-media-missing-package-expanded'
    $null = New-Item -Path $MediaRoot -ItemType Directory -Force
    $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
    [IO.File]::WriteAllBytes((Join-Path $MediaRoot 'setup.exe'), [byte[]]@(0x4D, 0x5A))
    [IO.File]::WriteAllBytes((Join-Path $MediaRoot 'Unrelated.msi'), [byte[]]@(0))
    [IO.File]::WriteAllText((Join-Path $MediaRoot 'Setup.ini'), @'
[Startup]
PackageName=Missing.msi

[Missing.msi]
Location=payload\Missing.msi
'@)

    InModuleScope InstallShield -Parameters @{ MediaRoot = $MediaRoot; ExpandedPath = $ExpandedPath } {
      $Selection = Get-InstallShieldExternalMediaSelection `
        -InstallerPath (Join-Path $MediaRoot 'setup.exe') -ExtractedPath $ExpandedPath

      $Selection.SelectionMethod | Should -Be 'SetupIniUnresolved'
      $Selection.SourceKind | Should -Be 'ExternalOrMissing'
      $Selection.SelectedMsiPath | Should -BeNullOrEmpty
      $Selection.Warnings | Should -Contain "Setup.ini selects 'Missing.msi', but that MSI path was not extracted."
    }
  }

  It 'Should reject an unresolved multi-MSI payload without an explicit override' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-ambiguous'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'First.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'Second.msi'), [byte[]]@(0))

      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath } {
        $MsiFiles = @(Get-ChildItem -LiteralPath $ExpandedPath -Filter '*.msi' -File)
        $Selection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExpandedPath -MsiFile $MsiFiles
        $Installer = [pscustomobject]@{
          ExtractedPath       = $ExpandedPath
          MsiPayloadSelection = $Selection
        }

        $Selection.SelectionMethod | Should -Be 'Unresolved'
        $Selection.SelectedMsiPath | Should -BeNullOrEmpty
        { Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false } | Should -Throw '*selection is ambiguous*'
        (Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern 'Second.msi' -NameWasSpecified $true).Name | Should -Be 'Second.msi'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
