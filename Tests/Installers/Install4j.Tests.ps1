. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'Install4j.psm1') -Force

  $Script:FixtureDirectory = $TestDrive
  $Script:GeneratedInstall4j11NoRuntime = Join-Path $Script:FixtureDirectory 'generated-install4j-11-nojre.exe'
  $Script:GeneratedInstall4j11BundledRuntime = Join-Path $Script:FixtureDirectory 'generated-install4j-11-bundled.exe'
  $Script:GeneratedInstall4j11X86 = Join-Path $Script:FixtureDirectory 'generated-install4j-11-x86.exe'
  $Script:GeneratedInstall4j11Arm64 = Join-Path $Script:FixtureDirectory 'generated-install4j-11-arm64.exe'
  $Script:GeneratedInstall4j11UserAssociation = Join-Path $Script:FixtureDirectory 'generated-install4j-11-user-association.exe'
  $ProgressPreference = 'SilentlyContinue'

  function Get-Install4jInstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url
  }

  function New-Install4jConfigFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Content
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    Set-Content -LiteralPath $FixturePath -Value $Content -Encoding UTF8
    return $FixturePath
  }

  function Write-BigEndianInt32 {
    param(
      [Parameter(Mandatory)]
      [System.IO.Stream]$Stream,

      [Parameter(Mandatory)]
      [int]$Value
    )

    $Bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
    $Stream.Write($Bytes, 0, $Bytes.Length)
  }

  function Write-BigEndianUInt16 {
    param(
      [Parameter(Mandatory)]
      [System.IO.Stream]$Stream,

      [Parameter(Mandatory)]
      [uint16]$Value
    )

    $Bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
    $Stream.Write($Bytes, 0, $Bytes.Length)
  }

  function Write-BigEndianInt64 {
    param(
      [Parameter(Mandatory)]
      [System.IO.Stream]$Stream,

      [Parameter(Mandatory)]
      [long]$Value
    )

    $Bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
    $Stream.Write($Bytes, 0, $Bytes.Length)
  }

  function New-Install4jEmbeddedConfigFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Content,

      [string]$EmbeddedName = 'i4jparams.conf'
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $NameBytes = [Text.Encoding]::UTF8.GetBytes($EmbeddedName)
    $ContentBytes = [Text.Encoding]::UTF8.GetBytes($Content)
    $Stream = [IO.File]::Open($FixturePath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $Prefix = [Text.Encoding]::ASCII.GetBytes('install4j launcher i4jruntime.jar;i4jparams.conf allinstdirs1234-5678-9012-3456')
      $Stream.Write($Prefix, 0, $Prefix.Length)
      Write-BigEndianInt32 -Stream $Stream -Value -387705899
      Write-BigEndianInt32 -Stream $Stream -Value 1
      Write-BigEndianUInt16 -Stream $Stream -Value ([uint16]$NameBytes.Length)
      $Stream.Write($NameBytes, 0, $NameBytes.Length)
      Write-BigEndianInt64 -Stream $Stream -Value ([long]$ContentBytes.Length)
      $Stream.Write($ContentBytes, 0, $ContentBytes.Length)
    } finally {
      $Stream.Dispose()
    }

    return $FixturePath
  }

  function New-Install4jLauncherConfigFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Content,

      [string]$Marker,

      [switch]$CorruptCrc32
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $EntryNameBytes = [Text.Encoding]::UTF8.GetBytes('i4jparams.conf')
    $ContentBytes = [Text.Encoding]::UTF8.GetBytes($Content)
    for ($Index = 0; $Index -lt $ContentBytes.Length; $Index++) { $ContentBytes[$Index] = $ContentBytes[$Index] -bxor 0x88 }

    $DataStream = [IO.MemoryStream]::new()
    $DataWriter = [IO.BinaryWriter]::new($DataStream, [Text.Encoding]::UTF8, $true)
    try {
      $DataWriter.Write([int]([string]::IsNullOrWhiteSpace($Marker) ? 1 : 2))
      if (-not [string]::IsNullOrWhiteSpace($Marker)) {
        $MarkerBytes = [Text.Encoding]::UTF8.GetBytes($Marker)
        $DataWriter.Write([int]2000)
        $DataWriter.Write([int]$MarkerBytes.Length)
        $DataWriter.Write($MarkerBytes)
      }
      $DataWriter.Write([int]2003)
      $DataWriter.Write([int]$EntryNameBytes.Length)
      $DataWriter.Write($EntryNameBytes)
      $DataWriter.Write([int]0)
      $DataWriter.Write([int]0)
      $DataWriter.Write([long]$ContentBytes.Length)
      $DataWriter.Write($ContentBytes)
      $DataWriter.Flush()
      $Data = $DataStream.ToArray()
    } finally {
      $DataWriter.Dispose()
      $DataStream.Dispose()
    }

    $Crc32 = Get-BinaryCrc32 -Bytes $Data
    if ($CorruptCrc32) { $Crc32 = $Crc32 -bxor 1 }
    $OutputStream = [IO.File]::Open($FixturePath, 'Create', 'Write', 'None')
    $OutputWriter = [IO.BinaryWriter]::new($OutputStream, [Text.Encoding]::UTF8, $true)
    try {
      $OutputWriter.Write([byte[]]::new(512))
      $OutputWriter.Write([byte[]](0xD5, 0x13, 0xE4, 0xE8))
      $OutputWriter.Write([uint32]1)
      $OutputWriter.Write([uint32]$Crc32)
      $OutputWriter.Write([long]$Data.Length)
      $OutputWriter.Write($Data)
    } finally {
      $OutputWriter.Dispose()
      $OutputStream.Dispose()
    }
    return $FixturePath
  }

  function New-Install4jLegacyLauncherFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Content,

      [Parameter(Mandatory)]
      [string]$Marker,

      [Parameter(Mandatory)]
      [ValidateSet(4, 8)]
      [int]$LengthSize,

      [switch]$Truncated
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $MarkerBytes = [Text.Encoding]::UTF8.GetBytes($Marker)
    $NameBytes = [Text.Encoding]::UTF8.GetBytes('i4jparams.conf')
    $ContentBytes = [Text.Encoding]::UTF8.GetBytes($Content)
    for ($Index = 0; $Index -lt $ContentBytes.Length; $Index++) { $ContentBytes[$Index] = $ContentBytes[$Index] -bxor 0x88 }

    $Stream = [IO.File]::Open($FixturePath, 'Create', 'Write', 'None')
    $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::UTF8, $true)
    try {
      $Writer.Write([byte[]]::new(512))
      $Writer.Write([byte[]](0xD5, 0x13, 0xE4, 0xE8))
      $Writer.Write([int]2)
      $Writer.Write([int]2000)
      $Writer.Write([int]$MarkerBytes.Length)
      $Writer.Write($MarkerBytes)
      $Writer.Write([int]2003)
      $Writer.Write([int]$NameBytes.Length)
      $Writer.Write($NameBytes)
      $Writer.Write([int]0)
      if ($LengthSize -eq 4) { $Writer.Write([int]$ContentBytes.Length) } else { $Writer.Write([long]$ContentBytes.Length) }
      $WriteLength = if ($Truncated) { [Math]::Max(0, $ContentBytes.Length - 8) } else { $ContentBytes.Length }
      $Writer.Write($ContentBytes, 0, $WriteLength)
    } finally {
      $Writer.Dispose()
      $Stream.Dispose()
    }
    return $FixturePath
  }

  $Script:SyntheticConfig = @'
<?xml version="1.0" encoding="UTF-8"?>
<config install4jVersion="9.0.7" install4jBuild="9184" type="windows" archive="false" bitness="64">
  <general applicationName="Synthetic install4j App" applicationVersion="1.2.3" mediaSetId="1" applicationId="1234-5678-9012-3456" mediaName="Synthetic" jreVersion="17" minJavaVersion="17" publisherName="Contoso Ltd." publisherURL="https://contoso.example" lzmaCompression="true" installerType="1" uninstallerFilename="uninstall" uninstallerDirectory="." defaultInstallationDirectory="{appdata}{/}Synthetic" privilegedInstallerRequest="true" />
  <compilerVariables>
    <variable name="marketingName" value="Synthetic install4j App" />
  </compilerVariables>
  <screens>
    <screen id="1">
      <actions>
        <action id="2">
          <java version="11.0.15" class="java.beans.XMLDecoder">
            <object class="com.install4j.runtime.beans.actions.misc.RequestPrivilegesAction" />
          </java>
          <actionLists />
        </action>
        <action id="3">
          <java version="11.0.15" class="java.beans.XMLDecoder">
            <object class="com.install4j.runtime.beans.actions.desktop.RegisterAddRemoveAction">
              <void property="itemName">
                <string>${compiler:marketingName} ${compiler:sys.version}</string>
              </void>
            </object>
          </java>
          <actionLists />
        </action>
      </actions>
    </screen>
  </screens>
</config>
'@
}

Describe 'install4j parser' {
  It 'Should resolve one complete catalog descriptor for every generation from 3 through 13' {
    InModuleScope Install4j {
      @($Script:Install4jFormats.Generation | Sort-Object -Unique) | Should -Be @(3..13)
      foreach ($Descriptor in $Script:Install4jFormats) {
        $Script:Install4jLauncherHandlers.ContainsKey($Descriptor.LauncherRoute) | Should -BeTrue
        $Script:Install4jContentTableHandlers.ContainsKey($Descriptor.ContentTableRoute) | Should -BeTrue
        $Script:Install4jPayloadHandlers.ContainsKey($Descriptor.PayloadRoute) | Should -BeTrue
        @($Descriptor.ValidationInvariants).Count | Should -BeGreaterThan 0
      }
    }
  }

  It 'Should route representative markers to exactly one catalog descriptor' -ForEach @(
    @{ Marker = 'L-INGO#196233333-'; Route = 'LegacyParameterBlock32'; Generation = 3 }
    @{ Marker = 'L-EJ_TECHNOLOGIES#1230003-'; Route = 'LegacyParameterBlock64'; Generation = 4 }
    @{ Marker = 'L-M5-EJT#12340033-'; Route = 'ModernOverlayV1'; Generation = 5 }
    @{ Marker = 'S-M9-EJT#1234-'; Route = 'ModernOverlayV1'; Generation = 9 }
    @{ Marker = 'L-M10-QOPPA_SOFTWARE_LLC#55423010001-'; Route = 'ModernOverlayV1'; Generation = 10 }
    @{ Marker = 'L-M12-PORTSWIGGER_LTD#61784010001-'; Route = 'ModernOverlayV1'; Generation = 12 }
  ) {
    InModuleScope Install4j -Parameters @{ Marker = $Marker; Route = $Route; ExpectedGeneration = $Generation } {
      param($Marker, $Route, $ExpectedGeneration)
      $Descriptor = Resolve-Install4jFormatDescriptor -Marker $Marker -LauncherRoute $Route
      $Descriptor.Generation | Should -Be $ExpectedGeneration
      $Descriptor.IsFallback | Should -BeFalse
    }
  }

  It 'Should decode generation 3 and generation 4 legacy startup-file framing' -ForEach @(
    @{ Generation = 3; Marker = 'L-INGO#196233333-'; LengthSize = 4; Route = 'LegacyParameterBlock32' }
    @{ Generation = 4; Marker = 'L-EJ_TECHNOLOGIES#1230003-'; LengthSize = 8; Route = 'LegacyParameterBlock64' }
  ) {
    $Fixture = New-Install4jLegacyLauncherFixture -Name "synthetic-install4j-$Generation.exe" -Content $Script:SyntheticConfig -Marker $Marker -LengthSize $LengthSize
    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture; ExpectedMarker = $Marker; ExpectedRoute = $Route; ExpectedLengthSize = $LengthSize; ExpectedContent = $Script:SyntheticConfig } {
      param($FixturePath, $ExpectedMarker, $ExpectedRoute, $ExpectedLengthSize, $ExpectedContent)
      Mock Get-PEOverlayOffset { 512 }
      $Launcher = Get-Install4jLegacyLauncherConfiguration -Path $FixturePath -LengthSize $ExpectedLengthSize
      $Bytes = Read-Install4jLauncherFile -Path $FixturePath -Entry $Launcher.Entries[0]
      $Launcher.Marker | Should -Be $ExpectedMarker
      $Launcher.Route | Should -Be $ExpectedRoute
      [Text.Encoding]::UTF8.GetString($Bytes) | Should -Be $ExpectedContent
    }
  }

  It 'Should reject a truncated generation 3 startup file' {
    $Fixture = New-Install4jLegacyLauncherFixture -Name 'synthetic-install4j-3-truncated.exe' -Content $Script:SyntheticConfig -Marker 'L-INGO#196233333-' -LengthSize 4 -Truncated
    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      { Get-Install4jLegacyLauncherConfiguration -Path $FixturePath -LengthSize 4 } | Should -Throw '*startup-file length*'
    }
  }

  It 'Should select the nearest compatible descriptor for a validated future modern marker' {
    $Fixture = New-Install4jLauncherConfigFixture -Name 'synthetic-install4j-14.exe' -Content $Script:SyntheticConfig -Marker 'S-M14-CONTOSO#1000-'
    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Probe = Get-Install4jLauncherProbe -Path $FixturePath
      $Probe.Descriptor.Generation | Should -Be 14
      $Probe.Descriptor.IsFallback | Should -BeTrue
      $Probe.Launcher.IsCrc32Valid | Should -BeTrue
      $Probe.Launcher.RemainingDataBytes | Should -Be 0
    }
  }

  It 'Should identify a complete pre-catalog launcher without guessing a supported route' {
    $Fixture = New-Install4jLauncherConfigFixture -Name 'synthetic-install4j-2.exe' -Content $Script:SyntheticConfig -Marker 'S-M2-CONTOSO#1000-'
    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Format = Get-Install4jFormatInfo -Path $FixturePath
      $Format.IsInstall4j | Should -BeTrue
      $Format.IsSupported | Should -BeFalse
      $Format.Marker | Should -Be 'S-M2-CONTOSO#1000-'
      $Format.FormatGeneration | Should -BeNullOrEmpty
      $Format.Warnings | Should -Contain "The launcher marker 'S-M2-CONTOSO#1000-' conflicts with install4j 9.0.7 encoded by i4jparams.conf; no supported descriptor was selected."
    }
  }

  It 'Should explain unsupported table-only media and list unresolved metadata' {
    $Fixture = New-Install4jEmbeddedConfigFixture -Name 'synthetic-install4j-unsupported-table.exe' -Content 'opaque payload' -EmbeddedName '0.dat'

    $Format = Get-Install4jFormatInfo -Path $Fixture
    $Info = Get-Install4jInfo -Path $Fixture

    $Format.IsInstall4j | Should -BeTrue
    $Format.IsSupported | Should -BeFalse
    $Format.Warnings | Should -Contain 'The install4j media is structurally identifiable, but no supported format descriptor could be selected from its launcher or configuration evidence.'
    $Info.Warnings | Should -Contain 'The install4j media is structurally identifiable, but no supported format descriptor could be selected from its launcher or configuration evidence.'
    $Info.UnresolvedFields | Should -Contain 'ProductCode'
    $Info.UnresolvedFields | Should -Contain 'WritesAppsAndFeaturesEntry'
    $Info.UnresolvedFields | Should -Contain 'Scope'
    $Info.UnresolvedFields | Should -Contain 'DefaultInstallLocation'
  }

  It 'Should reject a future launcher whose modern CRC invariant fails' {
    $Fixture = New-Install4jLauncherConfigFixture -Name 'synthetic-install4j-14-bad-crc.exe' -Content $Script:SyntheticConfig -Marker 'S-M14-CONTOSO#1000-' -CorruptCrc32
    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Format = Get-Install4jFormatInfo -Path $FixturePath
      $Format.IsInstall4j | Should -BeFalse
      $Format.IsSupported | Should -BeFalse
    }
  }

  It 'Should decode and CRC-check a synthetic launcher startup file' {
    $Fixture = New-Install4jLauncherConfigFixture -Name 'synthetic-install4j-launcher.exe' -Content $Script:SyntheticConfig

    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture; ExpectedContent = $Script:SyntheticConfig } {
      param($FixturePath, $ExpectedContent)
      Mock Get-PEOverlayOffset { 512 }
      $Launcher = Get-Install4jModernLauncherConfiguration -Path $FixturePath
      $Bytes = Read-Install4jLauncherFile -Path $FixturePath -Entry $Launcher.Entries[0]

      $Launcher.IsCrc32Valid | Should -BeTrue
      $Launcher.Entries[0].Name | Should -Be 'i4jparams.conf'
      [Text.Encoding]::UTF8.GetString($Bytes) | Should -Be $ExpectedContent
    }
  }

  It 'Should reject a launcher configuration with a bad CRC32' {
    $Fixture = New-Install4jLauncherConfigFixture -Name 'synthetic-install4j-bad-crc.exe' -Content $Script:SyntheticConfig -CorruptCrc32

    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      { Get-Install4jModernLauncherConfiguration -Path $FixturePath } | Should -Throw '*CRC32 is invalid*'
    }
  }

  It 'Should parse ProductCode, ARP fields, and dual-scope evidence from i4jparams.conf' {
    $Fixture = New-Install4jConfigFixture -Name 'i4jparams.conf' -Content $Script:SyntheticConfig
    $Info = Get-Install4jInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'install4j'
    $Info.ProductCode | Should -Be '1234-5678-9012-3456'
    $Info.DisplayName | Should -Be 'Synthetic install4j App 1.2.3'
    $Info.DisplayVersion | Should -Be '1.2.3'
    $Info.Publisher | Should -Be 'Contoso Ltd.'
    $Info.Architecture | Should -Be 'x64'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.Scope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.RegistryWrites.Name | Should -Contain 'DisplayName'
    $Info.RegistryWrites.Name | Should -Contain 'DisplayVersion'
  }

  It 'Should map explicit configuration bitness to concrete architecture' -ForEach @(
    @{ Bitness = '32'; Expected = 'x86' }
    @{ Bitness = '64'; Expected = 'x64' }
    @{ Bitness = 'arm64'; Expected = 'arm64' }
    @{ Bitness = 'aarch64'; Expected = 'arm64' }
  ) {
    $Config = $Script:SyntheticConfig -replace 'bitness="64"', "bitness=`"$Bitness`""
    $Fixture = New-Install4jConfigFixture -Name "i4jparams-$Bitness.conf" -Content $Config
    (Get-Install4jFormatInfo -Path $Fixture).Architecture | Should -Be $Expected
  }

  It 'Should retain a minimum Java requirement when no bundled-runtime version is encoded' {
    $Config = $Script:SyntheticConfig -replace ' jreVersion="17"', ''
    $Fixture = New-Install4jConfigFixture -Name 'i4jparams-no-runtime.conf' -Content $Config
    $Info = Get-Install4jInfo -Path $Fixture

    $Info.Config.General.JreVersion | Should -BeNullOrEmpty
    $Info.Config.General.MinimumJavaVersion | Should -Be '17'
    $Info.HasBundledRuntime | Should -BeFalse
    $Info.BundledRuntimeVersion | Should -BeNullOrEmpty
    $Info.MinimumJavaVersion | Should -Be '17'
  }

  It 'Should distinguish paired install4j 11 media with and without a bundled runtime' {
    if (-not (Test-Path -LiteralPath $Script:GeneratedInstall4j11NoRuntime -PathType Leaf) -or
      -not (Test-Path -LiteralPath $Script:GeneratedInstall4j11BundledRuntime -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The paired VM-generated install4j 11 runtime fixtures are not cached.'
      return
    }

    $NoRuntime = Get-Install4jInfo -Path $Script:GeneratedInstall4j11NoRuntime
    $Bundled = Get-Install4jInfo -Path $Script:GeneratedInstall4j11BundledRuntime

    $NoRuntime.HasBundledRuntime | Should -BeFalse
    $NoRuntime.BundledRuntimeVersion | Should -BeNullOrEmpty
    $NoRuntime.MinimumJavaVersion | Should -Be '11'
    $NoRuntime.BundledRuntimeArchive | Should -BeNullOrEmpty
    $Bundled.HasBundledRuntime | Should -BeTrue
    $Bundled.BundledRuntimeVersion | Should -Be '21.0.12'
    $Bundled.MinimumJavaVersion | Should -Be '11'
    $Bundled.BundledRuntimeArchive | Should -Be 'jre.tar.gz'
    $Bundled.RuntimeEvidence | Should -Contain "i4jparams.conf declares bundled Java runtime version '21.0.12'."
    $Bundled.RuntimeEvidence | Should -Contain "The installer startup-file catalog contains 'jre.tar.gz'."
    $Bundled.Warnings | Should -BeNullOrEmpty
  }

  It 'Should distinguish controlled install4j 11 x86, x64, and ARM64 media' {
    $Fixtures = [ordered]@{
      x86   = $Script:GeneratedInstall4j11X86
      x64   = $Script:GeneratedInstall4j11NoRuntime
      arm64 = $Script:GeneratedInstall4j11Arm64
    }
    if (@($Fixtures.Values | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count -gt 0) {
      Set-ItResult -Skipped -Because 'The VM-generated install4j 11 architecture fixtures are not all cached.'
      return
    }

    foreach ($ExpectedArchitecture in $Fixtures.Keys) {
      $Info = Get-Install4jInfo -Path $Fixtures[$ExpectedArchitecture]
      $Info.Architecture | Should -Be $ExpectedArchitecture
      $Info.FormatGeneration | Should -Be 11
      $Info.BuilderVersion | Should -Be '11.0.5'
      $Info.ProductCode | Should -Be '0804-2950-8354-4050'
      $Info.Warnings | Should -BeNullOrEmpty
    }

    # install4j records ARM64 as 64-bit in config XML; the PE machine distinguishes it from x64.
    (Get-Install4jInfo -Path $Script:GeneratedInstall4j11Arm64).Config.Bitness | Should -Be '64'
  }

  It 'Should recover user-fallback scope and defaulted file-association properties from controlled media' {
    if (-not (Test-Path -LiteralPath $Script:GeneratedInstall4j11UserAssociation -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-generated install4j 11 scope and association fixture is not cached.'
      return
    }

    $Info = Get-Install4jInfo -Path $Script:GeneratedInstall4j11UserAssociation
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.Config.RequestPrivileges.FailIfNotObtainedWin | Should -BeFalse
    $Info.FileExtensions | Should -Be @('i4jtest')
    $Info.RegistryAssociationInfo.FileExtensionAssociations[0].Description | Should -Be 'Synthetic install4j document'
    $Info.RegistryAssociationInfo.FileExtensionAssociations[0].IsSelectedByDefault | Should -BeTrue
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should identify a privilege action that fails without elevation as machine-only' {
    $PrivilegeAction = @'
            <object class="com.install4j.runtime.beans.actions.misc.RequestPrivilegesAction">
              <void property="obtainIfNormalWin"><boolean>true</boolean></void>
              <void property="failIfNotObtainedWin"><boolean>true</boolean></void>
            </object>
'@
    $Config = $Script:SyntheticConfig -replace '<object class="com.install4j.runtime.beans.actions.misc.RequestPrivilegesAction" />', $PrivilegeAction.Trim()
    $Fixture = New-Install4jConfigFixture -Name 'i4jparams-machine-only.conf' -Content $Config
    $Info = Get-Install4jInfo -Path $Fixture

    $Info.Scope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.SupportsDualScope | Should -BeFalse
  }

  It 'Should parse a direct i4jparams.conf entry from the install4j embedded file table' {
    $Fixture = New-Install4jEmbeddedConfigFixture -Name 'synthetic-install4j-table.exe' -Content $Script:SyntheticConfig
    $Info = Get-Install4jInfo -Path $Fixture

    $Info.ProductCode | Should -Be '1234-5678-9012-3456'
    $Info.DisplayName | Should -Be 'Synthetic install4j App 1.2.3'
    $Info.EmbeddedFileTables | Should -HaveCount 1
    $Info.EmbeddedFileTables[0].Entries[0].Name | Should -Be 'i4jparams.conf'
  }

  It 'Should read Windows CreateFileAssociationAction entries from config XML' {
    $AssociationAction = @'
        <action id="4">
          <java version="11.0.15" class="java.beans.XMLDecoder">
            <object class="com.install4j.runtime.beans.actions.desktop.CreateFileAssociationAction">
              <void property="extension"><string>synthetic</string></void>
              <void property="description"><string>Synthetic document</string></void>
              <void property="launcherId"><string>42</string></void>
              <void property="windows"><boolean>true</boolean></void>
              <void property="selected"><boolean>true</boolean></void>
            </object>
          </java>
        </action>
'@
    $Config = $Script:SyntheticConfig -replace '</actions>', "$AssociationAction</actions>"
    $Fixture = New-Install4jConfigFixture -Name 'i4jparams-association.conf' -Content $Config

    $Info = Get-Install4jInfo -Path $Fixture

    $Info.FileExtensions | Should -Be @('synthetic')
    $Info.RegistryAssociationInfo.FileExtensionAssociations[0].Description | Should -Be 'Synthetic document'
    $Info.RegistryAssociationInfo.FileExtensionAssociations[0].LauncherId | Should -Be '42'
    $Info.RegistryAssociationInfo.FileExtensionAssociations[0].IsSelectedByDefault | Should -BeTrue
  }

  It 'Should expand a direct embedded install4j file safely' {
    $Fixture = New-Install4jEmbeddedConfigFixture -Name 'synthetic-install4j-expand.exe' -Content $Script:SyntheticConfig
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-install4j-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'i4jparams.conf' -CollisionAction Rename
      $ConfigPath = Join-Path $Result 'i4jparams.conf'

      $ConfigPath | Should -Exist
      (Get-Content -LiteralPath $ConfigPath -Raw) | Should -BeLike '*applicationId="1234-5678-9012-3456"*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject an install4j embedded file that escapes the destination' {
    $Fixture = New-Install4jEmbeddedConfigFixture -Name 'synthetic-install4j-traversal.exe' -Content $Script:SyntheticConfig -EmbeddedName '..\escape.xml'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-install4j-traversal-expanded'
    $EscapedPath = Join-Path $Script:FixtureDirectory 'escape.xml'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $EscapedPath -Force -ErrorAction SilentlyContinue

    try {
      { Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name '*' -CollisionAction Rename } | Should -Throw '*escapes the destination*'
      $EscapedPath | Should -Not -Exist
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path $EscapedPath -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover ProductCode and version metadata from the install4j 9 Windows launcher' {
    $Fixture = Get-Install4jInstallerFixture -Name 'install4j_windows-x64_9_0_7.exe' -Url 'https://download.ej-technologies.com/install4j/install4j_windows-x64_9_0_7.exe'
    $Info = Get-Install4jInfo -Path $Fixture

    $Info.ProductCode | Should -Be '8611-7263-0882-4541'
    $Info.DisplayVersion | Should -Be '9.0.7'
    $Info.Publisher | Should -Be 'ej-technologies GmbH'
    $Info.Architecture | Should -Be 'x64'
    $Info.EmbeddedFiles | Should -Contain 'i4jparams.conf'
    $Info.EmbeddedFileTables[0].Entries[0].Name | Should -Be '0.dat'
    $Info.Config.Source | Should -Be 'LauncherStartupFile'
    $Info.LauncherConfiguration.IsCrc32Valid | Should -BeTrue
    $Info.LauncherConfiguration.Entries.Name | Should -Contain 'i4jparams.conf'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should route markerless install4j 11 application media from validated configuration evidence' {
    if (-not (Test-Path -LiteralPath $Script:GeneratedInstall4j11NoRuntime -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-generated install4j 11 runtime-independent fixture is not cached.'
      return
    }

    $Format = Get-Install4jFormatInfo -Path $Script:GeneratedInstall4j11NoRuntime
    $Info = Get-Install4jInfo -Path $Script:GeneratedInstall4j11NoRuntime

    $Format.IsInstall4j | Should -BeTrue
    $Format.IsSupported | Should -BeTrue
    $Format.FormatGeneration | Should -Be 11
    $Format.BuilderVersion | Should -Be '11.0.5'
    $Format.BuilderBuild | Should -Be '11153'
    $Format.Marker | Should -BeNullOrEmpty
    $Format.LauncherRoute | Should -Be 'ModernOverlayV1'
    $Format.Evidence | Should -Contain 'The launcher omitted a catalog marker; validated i4jparams.conf selected install4j generation 11.'
    $Info.ProductCode | Should -Be '0804-2950-8354-4050'
    $Info.DisplayName | Should -Be 'Hello World Suite 11.0'
    $Info.DisplayVersion | Should -Be '11.0'
    $Info.Architecture | Should -Be 'x64'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.CanExpand | Should -BeTrue
    $Info.Warnings | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -BeNullOrEmpty
  }

  It 'Should selectively extract configuration from markerless install4j 11 application media' {
    if (-not (Test-Path -LiteralPath $Script:GeneratedInstall4j11NoRuntime -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-generated install4j 11 runtime-independent fixture is not cached.'
      return
    }

    $ExpandedPath = Join-Path $Script:FixtureDirectory 'generated-install4j-11-nojre-expanded'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Result = Expand-Install4jInstaller -Path $Script:GeneratedInstall4j11NoRuntime -DestinationPath $ExpandedPath -Name 'i4jparams.conf' -CollisionAction Rename
      $ConfigPath = Join-Path $Result 'i4jparams.conf'
      $ConfigPath | Should -Exist
      (Get-Content -LiteralPath $ConfigPath -Raw) | Should -BeLike '*applicationId="0804-2950-8354-4050"*'
      @(Get-ChildItem -LiteralPath $Result -Recurse -File).Count | Should -Be 1
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should route official install4j <Version> Windows media through generation <Generation>' -ForEach @(
    @{ Version = '3.2.5'; Generation = 3; Name = 'install4j_windows_3_2_5.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows_3_2_5.exe' }
    @{ Version = '4.1'; Generation = 4; Name = 'install4j_windows-x64_4_1.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_4_1.exe' }
    @{ Version = '4.2.8'; Generation = 4; Name = 'install4j_windows-x64_4_2_8.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_4_2_8.exe' }
    @{ Version = '5.0.11'; Generation = 5; Name = 'install4j_windows-x64_5_0_11.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_5_0_11.exe' }
    @{ Version = '5.1.15'; Generation = 5; Name = 'install4j_windows-x64_5_1_15.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_5_1_15.exe' }
    @{ Version = '6.1.6'; Generation = 6; Name = 'install4j_windows-x64_6_1_6.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_6_1_6.exe' }
    @{ Version = '7.0.12'; Generation = 7; Name = 'install4j_windows-x64_7_0_12.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_7_0_12.exe' }
    @{ Version = '8.0.11'; Generation = 8; Name = 'install4j_windows-x64_8_0_11.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_8_0_11.exe' }
    @{ Version = '9.0.7'; Generation = 9; Name = 'install4j_windows-x64_9_0_7.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_9_0_7.exe' }
    @{ Version = '10.0.9'; Generation = 10; Name = 'install4j_windows-x64_10_0_9.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_10_0_9.exe' }
    @{ Version = '11.0.5'; Generation = 11; Name = 'install4j_windows-x64_11_0_5.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_11_0_5.exe' }
    @{ Version = '12.0.5'; Generation = 12; Name = 'install4j_windows-x64_12_0_5.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_12_0_5.exe' }
    @{ Version = '13.0.2'; Generation = 13; Name = 'install4j_windows-x64_13_0_2.exe'; Url = 'https://download.ej-technologies.com/install4j/install4j_windows-x64_13_0_2.exe' }
  ) {
    $Fixture = Get-Install4jInstallerFixture -Name $Name -Url $Url
    $Format = Get-Install4jFormatInfo -Path $Fixture

    $Format.IsInstall4j | Should -BeTrue
    $Format.IsSupported | Should -BeTrue
    $Format.FormatGeneration | Should -Be $Generation
    $Format.IsFallback | Should -BeFalse
    $Format.Warnings | Should -BeNullOrEmpty
  }

  It 'Should parse behaviorally distinct package media from <Package>' -ForEach @(
    @{
      Package = 'PortSwigger.BurpSuite.Community'; Name = 'PortSwigger.BurpSuite.Community-2026.3.3.exe'
      Url = 'https://portswigger-cdn.net/burp/releases/download?product=community&version=2026.3.3&type=WindowsX64'
      Generation = 12; ProductCode = '9806-1938-4586-6531'; Scope = $null
    }
    @{
      Package = 'ZAP.ZAP'; Name = 'ZAP_2_17_0_windows.exe'
      Url = 'https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2_17_0_windows.exe'
      Generation = 10; ProductCode = 'ZAP'; Scope = 'machine'
    }
    @{
      Package = 'Qoppa.PDFStudio'; Name = 'Qoppa.PDFStudio-2024.0.1.exe'
      Url = 'https://download.qoppa.com/pdfstudio/v2024/PDFStudio_v2024_0_1_win64.exe'
      Generation = 10; ProductCode = '6111-5741-2268-8723'; Scope = 'machine'
    }
  ) {
    $Fixture = Get-Install4jInstallerFixture -Name $Name -Url $Url
    $Info = Get-Install4jInfo -Path $Fixture

    $Info.FormatGeneration | Should -Be $Generation
    $Info.ProductCode | Should -Be $ProductCode
    $Info.Scope | Should -Be $Scope
    $Info.Config.Source | Should -Be 'LauncherStartupFile'
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should extract generation 3 inline and generation 4 split application archives' {
    $Generation3 = Get-Install4jInstallerFixture -Name 'install4j_windows_3_2_5.exe' -Url 'https://download.ej-technologies.com/install4j/install4j_windows_3_2_5.exe'
    $Generation4 = Get-Install4jInstallerFixture -Name 'install4j_windows-x64_4_2_8.exe' -Url 'https://download.ej-technologies.com/install4j/install4j_windows-x64_4_2_8.exe'
    $Generation3Output = Join-Path $Script:FixtureDirectory 'install4j-generation-3-expanded'
    $Generation4Output = Join-Path $Script:FixtureDirectory 'install4j-generation-4-expanded'
    Remove-Item -LiteralPath $Generation3Output -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Generation4Output -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $null = Expand-Install4jInstaller -Path $Generation3 -DestinationPath $Generation3Output -Name 'README.txt' -CollisionAction Rename
      $null = Expand-Install4jInstaller -Path $Generation4 -DestinationPath $Generation4Output -Name 'samples\hello\media\README.txt' -CollisionAction Rename
      @(Get-ChildItem -LiteralPath $Generation3Output -Recurse -File -Filter README.txt).Count | Should -BeGreaterThan 0
      Join-Path $Generation4Output 'samples\hello\media\README.txt' | Should -Exist
    } finally {
      Remove-Item -LiteralPath $Generation3Output -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath $Generation4Output -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should decode the real launcher i4jparams.conf startup file' {
    $Fixture = Get-Install4jInstallerFixture -Name 'install4j_windows-x64_9_0_7.exe' -Url 'https://download.ej-technologies.com/install4j/install4j_windows-x64_9_0_7.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'install4j-real-config-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'i4jparams.conf' -CollisionAction Rename
      $ConfigText = Get-Content -LiteralPath (Join-Path $Result 'i4jparams.conf') -Raw

      $ConfigText | Should -BeLike '*applicationId="8611-7263-0882-4541"*'
      $ConfigText | Should -BeLike '*applicationVersion="9.0.7"*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should decode and selectively expand the real install4j LZMA content archive' {
    $Fixture = Get-Install4jInstallerFixture -Name 'install4j_windows-x64_9_0_7.exe' -Url 'https://download.ej-technologies.com/install4j/install4j_windows-x64_9_0_7.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'install4j-real-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'README.txt' -CollisionAction Rename
      $ReadmePath = Join-Path $Result 'README.txt'

      $ReadmePath | Should -Exist
      (Get-Item -LiteralPath $ReadmePath).Length | Should -BeGreaterThan 0
      $ExtractedFiles = @(Get-ChildItem -Path $Result -Recurse -File)
      $ExtractedFiles.Count | Should -BeGreaterThan 0
      $ExtractedFiles.Name | Should -Not -Contain 'install4j.exe'
      @($ExtractedFiles | Where-Object Name -NE 'README.txt') | Should -BeNullOrEmpty
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject an install4j LZMA payload above the configured output limit' {
    $Fixture = Get-Install4jInstallerFixture -Name 'install4j_windows-x64_9_0_7.exe' -Url 'https://download.ej-technologies.com/install4j/install4j_windows-x64_9_0_7.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'install4j-limited-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      { Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'README.txt' -MaximumExpandedBytes 1048576 -CollisionAction Rename } | Should -Throw '*exceeding the 1048576-byte limit*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
