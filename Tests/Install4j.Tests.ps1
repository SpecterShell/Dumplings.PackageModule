BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Install4j.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\Install4j'
  $ProgressPreference = 'SilentlyContinue'

  function Get-Install4jInstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
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

      [switch]$CorruptCrc32
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $EntryNameBytes = [Text.Encoding]::UTF8.GetBytes('i4jparams.conf')
    $ContentBytes = [Text.Encoding]::UTF8.GetBytes($Content)
    for ($Index = 0; $Index -lt $ContentBytes.Length; $Index++) { $ContentBytes[$Index] = $ContentBytes[$Index] -bxor 0x88 }

    $DataStream = [IO.MemoryStream]::new()
    $DataWriter = [IO.BinaryWriter]::new($DataStream, [Text.Encoding]::UTF8, $true)
    try {
      $DataWriter.Write([int]1)
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
  It 'Should decode and CRC-check a synthetic launcher startup file' {
    $Fixture = New-Install4jLauncherConfigFixture -Name 'synthetic-install4j-launcher.exe' -Content $Script:SyntheticConfig

    InModuleScope Install4j -Parameters @{ FixturePath = $Fixture; ExpectedContent = $Script:SyntheticConfig } {
      param($FixturePath, $ExpectedContent)
      Mock Get-PEOverlayOffset { 512 }
      $Launcher = Get-Install4jLauncherConfiguration -Path $FixturePath
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
      { Get-Install4jLauncherConfiguration -Path $FixturePath } | Should -Throw '*CRC32 is invalid*'
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
      $Result = Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'i4jparams.conf'
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
      { Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name '*' } | Should -Throw '*escapes the destination*'
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

  It 'Should decode the real launcher i4jparams.conf startup file' {
    $Fixture = Get-Install4jInstallerFixture -Name 'install4j_windows-x64_9_0_7.exe' -Url 'https://download.ej-technologies.com/install4j/install4j_windows-x64_9_0_7.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'install4j-real-config-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'i4jparams.conf'
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
      $Result = Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'README.txt'
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
      { Expand-Install4jInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'README.txt' -MaximumExpandedBytes 1048576 } | Should -Throw '*exceeding the 1048576-byte limit*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
