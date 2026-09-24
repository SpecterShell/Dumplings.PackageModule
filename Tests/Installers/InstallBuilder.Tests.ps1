. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerDiagnostics.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PEArchitecture.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PEDependency.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'InstallBuilder.psm1') -Force

  $Script:InstallBuilderLegacyFixture = Get-DumplingsTestFixture `
    -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'installbuilder-3.6.0-windows-installer.exe') `
    -Uri 'https://web.archive.org/web/20060419104749id_/http://www.bitrock.com/installbuilder-3.6.0-windows-installer.exe' `
    -Sha256 '8A74835E0693945281739841D53D6890F147A8CEF2FEC03714B9D903ECB2F9ED'

  $Script:InstallBuilderDeflateFixture = Get-DumplingsTestFixture `
    -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'jxplorer-3.3.1.2-windows-installer.exe') `
    -Uri 'https://downloads.sourceforge.net/project/jxplorer/jxplorer/version%203.3.1.2/jxplorer-3.3.1.2-windows-installer.exe' `
    -Sha256 'C1FE14A60BC6AA909EA8C1D5F09EB7426722BDD90634B451C12D1A32D10FF67B'

  $Script:InstallBuilderLzmaFixture = Get-DumplingsTestFixture `
    -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'installbuilder-9.5.5-windows-installer.exe') `
    -Uri 'https://web.archive.org/web/20150513id_/http://installbuilder.bitrock.com/installbuilder-9.5.5-windows-installer.exe' `
    -Sha256 'E7BEA2FAE49D9291346154D631FFA9A197CF2C88394416B351867B385DCE159F'

  $Script:InstallBuilderMultiVfsFixture = Get-DumplingsTestFixture `
    -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'installbuilder-enterprise-8.2.0-windows-installer.exe') `
    -Uri 'https://web.archive.org/web/20120607082324id_/http://installbuilder.bitrock.com/installbuilder-enterprise-8.2.0-windows-installer.exe' `
    -Sha256 '92CF98DC56AF7631D237CC41A83DB1660D9A66657BD7DCB9DFA29F6205C563F7'

  $Script:InstallBuilderRebrandFixture = Get-DumplingsTestFixture `
    -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'installbuilder-23.1.0-windows-installer.exe') `
    -Uri 'https://web.archive.org/web/20230130id_/https://releases.bitrock.com/installbuilder/installbuilder-23.1.0-windows-installer.exe' `
    -Sha256 'C4434CFD64491E18A28D893FBD8D3535448FD22DDF869DE7AE61F190CE88891E'

  $Script:InstallBuilderCurrentFixture = Get-DumplingsTestFixture `
    -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'installbuilder-26.8.0-windows-x64-installer.exe') `
    -Uri 'https://releases.installbuilder.com/installbuilder/installbuilder-26.8.0-windows-x64-installer.exe' `
    -Sha256 'D731DFF8E6C138C9E8866FD8C2D530CA479B62ABCF93E87360C08654712FBEA7'

  $Script:FixtureDirectory = $TestDrive

  function New-TestInstallBuilderFixture {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$ProjectXml,
      [ValidateRange(0, 10000)][int]$IncidentalZlibStartCount = 0
    )
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try {
      $Bytes = [Text.Encoding]::UTF8.GetBytes($ProjectXml)
      $Encoder.Write($Bytes, 0, $Bytes.Length)
    } finally { $Encoder.Dispose() }
    $Path = Join-Path $Script:FixtureDirectory $Name
    $Noise = [byte[]]::new($IncidentalZlibStartCount * 2)
    for ($Index = 0; $Index -lt $IncidentalZlibStartCount; $Index++) {
      $Noise[$Index * 2] = 0x78
      $Noise[$Index * 2 + 1] = 0xFF
    }
    [IO.File]::WriteAllBytes($Path, [Text.Encoding]::ASCII.GetBytes("MZ`0MetakitVfs`0project.xml`0manifest.txt`0cookfsinfo.txt`0") + $Noise + $Compressed.ToArray())
    return $Path
  }

  function ConvertTo-TestBigEndianUInt32 {
    param([Parameter(Mandatory)][uint32]$Value)
    $Bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($Bytes)
    return $Bytes
  }

  function ConvertTo-TestBigEndianUInt64 {
    param([Parameter(Mandatory)][uint64]$Value)
    $Bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($Bytes)
    return $Bytes
  }

  function New-TestCookfsInstallBuilderFixture {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$ProjectXml,
      [ValidateSet('None', 'BZip2')][string]$Compression = 'None',
      [ValidateSet('md5', 'crc32')][string]$PageHashAlgorithm = 'md5',
      [uint64]$ModificationTimeUnixSeconds = 1700000000,
      [switch]$UnsupportedCookfsCompression,
      [switch]$CorruptPageHash
    )

    # The fixture is a small unencrypted CFS0002 archive with one BitRock split
    # file. It exercises static page parsing and logical-file reassembly.
    $Files = @(
      [pscustomobject]@{ Name = 'app.exe'; Content = [Text.Encoding]::ASCII.GetBytes('first-') },
      [pscustomobject]@{ Name = 'app.exe___bitrockBigFile1'; Content = [Text.Encoding]::ASCII.GetBytes('second') },
      [pscustomobject]@{ Name = 'readme.txt'; Content = [Text.Encoding]::ASCII.GetBytes('readme') }
    )
    $Index = [IO.MemoryStream]::new()
    try {
      $Magic = [Text.Encoding]::ASCII.GetBytes('CFS2.200')
      $Index.Write($Magic, 0, $Magic.Length)
      $Count = ConvertTo-TestBigEndianUInt32 -Value ([uint32]$Files.Count)
      $Index.Write($Count, 0, $Count.Length)
      for ($Page = 0; $Page -lt $Files.Count; $Page++) {
        $File = $Files[$Page]
        $NameBytes = [Text.Encoding]::UTF8.GetBytes($File.Name)
        $Index.WriteByte([byte]$NameBytes.Length)
        $Index.Write($NameBytes, 0, $NameBytes.Length)
        $Index.WriteByte(0)
        $Timestamp = ConvertTo-TestBigEndianUInt64 -Value $ModificationTimeUnixSeconds
        $Index.Write($Timestamp, 0, $Timestamp.Length)
        foreach ($Value in @([uint32]1, [uint32]$Page, [uint32]0, [uint32]$File.Content.Length)) {
          $Bytes = ConvertTo-TestBigEndianUInt32 -Value $Value
          $Index.Write($Bytes, 0, $Bytes.Length)
        }
      }
      $MetadataKey = [Text.Encoding]::UTF8.GetBytes('cookfs.pagehash')
      $MetadataValue = [Text.Encoding]::UTF8.GetBytes($PageHashAlgorithm)
      $Metadata = $MetadataKey + [byte]0 + $MetadataValue
      foreach ($Value in @([uint32]1, [uint32]$Metadata.Length)) {
        $Bytes = ConvertTo-TestBigEndianUInt32 -Value $Value
        $Index.Write($Bytes, 0, $Bytes.Length)
      }
      $Index.Write($Metadata, 0, $Metadata.Length)
      $StoredIndex = [byte[]](0) + $Index.ToArray()
    } finally {
      $Index.Dispose()
    }

    $Pages = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($File in $Files) {
      if ($Compression -eq 'BZip2') {
        $CompressedPage = [IO.MemoryStream]::new()
        try {
          $CompressedPage.WriteByte(2)
          $CompressedPage.Write([byte[]]::new(4), 0, 4)
          $Encoder = [SharpCompress.Compressors.BZip2.BZip2Stream]::new($CompressedPage, [SharpCompress.Compressors.CompressionMode]::Compress, $true)
          try { $Encoder.Write($File.Content, 0, $File.Content.Length) } finally { $Encoder.Dispose() }
          $Pages.Add($CompressedPage.ToArray())
        } finally {
          $CompressedPage.Dispose()
        }
      } else {
        $Pages.Add(([byte[]](0) + $File.Content))
      }
    }
    $Cookfs = [IO.MemoryStream]::new()
    try {
      foreach ($Page in $Pages) { $Cookfs.Write($Page, 0, $Page.Length) }
      $PageHashes = [IO.MemoryStream]::new()
      try {
        foreach ($File in $Files) {
          if ($PageHashAlgorithm -eq 'crc32') {
            $PageHashes.Write([byte[]]::new(8), 0, 8)
            $LengthBytes = ConvertTo-TestBigEndianUInt32 -Value ([uint32]$File.Content.Length)
            $CrcBytes = ConvertTo-TestBigEndianUInt32 -Value ([uint32](Get-BinaryCrc32 -Bytes $File.Content))
            $PageHashes.Write($LengthBytes, 0, $LengthBytes.Length)
            $PageHashes.Write($CrcBytes, 0, $CrcBytes.Length)
          } else {
            $Hash = [Security.Cryptography.MD5]::HashData($File.Content)
            $PageHashes.Write($Hash, 0, $Hash.Length)
          }
        }
        $PageHashBytes = $PageHashes.ToArray()
      } finally { $PageHashes.Dispose() }
      if ($CorruptPageHash) { $PageHashBytes[0] = $PageHashBytes[0] -bxor 0xFF }
      $Cookfs.Write($PageHashBytes, 0, $PageHashBytes.Length)
      foreach ($Page in $Pages) {
        $Bytes = ConvertTo-TestBigEndianUInt32 -Value ([uint32]$Page.Length)
        $Cookfs.Write($Bytes, 0, $Bytes.Length)
      }
      $Cookfs.Write($StoredIndex, 0, $StoredIndex.Length)
      foreach ($Value in @([uint32]$StoredIndex.Length, [uint32]$Pages.Count)) {
        $Bytes = ConvertTo-TestBigEndianUInt32 -Value $Value
        $Cookfs.Write($Bytes, 0, $Bytes.Length)
      }
      $Cookfs.WriteByte(0)
      $Footer = [Text.Encoding]::ASCII.GetBytes('CFS0002')
      $Cookfs.Write($Footer, 0, $Footer.Length)

      $Compressed = [IO.MemoryStream]::new()
      $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
      try {
        $ProjectBytes = [Text.Encoding]::UTF8.GetBytes($ProjectXml)
        $Encoder.Write($ProjectBytes, 0, $ProjectBytes.Length)
      } finally {
        $Encoder.Dispose()
      }
      try {
        $Path = Join-Path $Script:FixtureDirectory $Name
        # A real PE prefix lets structural analyzer tests enforce content-first detection while
        # the appended bytes remain a compact synthetic InstallBuilder container.
        $PeBytes = [IO.File]::ReadAllBytes((Join-Path $PSHOME 'pwsh.exe'))
        $CookfsOffset = $PeBytes.Length
        $Prefix = $PeBytes + $Cookfs.ToArray() + [Text.Encoding]::ASCII.GetBytes("MetakitVfs`0project.xml`0")
        [IO.File]::WriteAllBytes($Path, $Prefix + $Compressed.ToArray())
        if ($UnsupportedCookfsCompression) {
          $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
          try {
            $Stream.Position = $CookfsOffset # First CookFS page follows the PE prefix.
            $Stream.WriteByte(255)
          } finally {
            $Stream.Dispose()
          }
        }
        return $Path
      } finally {
        $Compressed.Dispose()
      }
    } finally {
      $Cookfs.Dispose()
    }
  }
}

Describe 'InstallBuilder static parser' {
  It 'Should not exhaust project candidates on incidental 0x78 bytes' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-zlib-candidates.exe' -ProjectXml '<project><shortName>Candidate</shortName><version>1.0</version></project>' -IncidentalZlibStartCount 5000

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.DisplayName | Should -Be 'Candidate'
    $Info.DisplayVersion | Should -Be '1.0'
  }

  It 'Should recover a zlib project record and parse product, ARP, and scope evidence' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder.exe' -ProjectXml @'
<project>
  <shortName>Example</shortName>
  <fullName>Example InstallBuilder Product</fullName>
  <version>1.2.3</version>
  <vendor>Example Vendor</vendor>
  <createWindowsARPEntry>0</createWindowsARPEntry>
  <requireInstallationByRootUser>1</requireInstallationByRootUser>
  <postUninstallerCreationActionList><runProgram/></postUninstallerCreationActionList>
  <readyToInstallActionList>
    <registrySet>
      <key>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Example</key>
      <name>DisplayName</name>
      <type>REG_SZ</type>
      <value>Example InstallBuilder Product</value>
    </registrySet>
  </readyToInstallActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'exe'
    $Info.ProductCode | Should -Be 'Example'
    $Info.DisplayName | Should -Be 'Example InstallBuilder Product'
    $Info.DisplayVersion | Should -Be '1.2.3'
    $Info.Publisher | Should -Be 'Example Vendor'
    $Info.Scope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.WritesBuiltInArp | Should -BeFalse
    $Info.RegistryWrites | Should -HaveCount 1
  }

  It 'Should keep hidden custom ARP evidence out of WinGet-facing fields' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-hidden-arp.exe' -ProjectXml @'
<project>
  <fullName>Hidden Product</fullName><version>1.0</version><vendor>Example Vendor</vendor>
  <readyToInstallActionList><registrySet><key>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden Product 1.0</key><name>SystemComponent</name><type>REG_DWORD</type><value>2</value></registrySet></readyToInstallActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.AppsAndFeaturesEntries | Should -HaveCount 0
    $Info.HiddenArpEntries | Should -HaveCount 1
    $Info.HiddenArpEntries[0].ProductCode | Should -Be 'Hidden Product 1.0'
    $Info.HiddenArpEntries[0].SystemComponent | Should -Be '2'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.ARP.HiddenOnly'
  }

  It 'Should use explicit HKCU ARP evidence without treating shortcut scope as package scope' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-user-arp.exe' -ProjectXml @'
<project>
  <fullName>User Product</fullName><version>2.0</version><vendor>Example Vendor</vendor>
  <createWindowsARPEntry>0</createWindowsARPEntry><requestedExecutionLevel>asInvoker</requestedExecutionLevel><installationScope>allusers</installationScope>
  <readyToInstallActionList><registrySet><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\User.Product</key><name>DisplayName</name><value>User Product</value></registrySet></readyToInstallActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.ProductCode | Should -Be 'User.Product'
    $Info.Scope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.ShortcutScope | Should -Be 'allusers'
  }

  It 'Should reconstruct the documented built-in ARP value set' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-built-in-arp.exe' -ProjectXml @'
<project>
  <fullName>ARP Product</fullName><version>3.4.5</version><vendor>Example Vendor</vendor>
  <productDisplayIcon>${installdir}/icons/app.ico</productDisplayIcon><productUrlInfoAbout>https://example.test/</productUrlInfoAbout>
  <productComments>Example comments</productComments><productContact>support@example.test</productContact><productUrlHelpLink>https://example.test/help</productUrlHelpLink>
  <uninstallerName>remove-product</uninstallerName><uninstallerDirectory>${installdir}/maintenance</uninstallerDirectory>
  <parameterList><directoryParameter><name>installdir</name><value>%ProgramFiles(x86)%\ARP Product</value></directoryParameter></parameterList>
</project>
'@

    $Entry = (Get-InstallBuilderInfo -Path $Fixture).VisibleArpEntries[0]

    $Entry.UninstallString | Should -Be '"%ProgramFiles(x86)%\ARP Product\maintenance\remove-product.exe"'
    $Entry.DisplayIcon | Should -Be '%ProgramFiles(x86)%\ARP Product/icons/app.ico'
    $Entry.InstallLocation | Should -Be '%ProgramFiles(x86)%\ARP Product'
    $Entry.UrlInfoAbout | Should -Be 'https://example.test/'
    $Entry.HelpLink | Should -Be 'https://example.test/help'
    $Entry.NoModify | Should -Be 1
    $Entry.NoRepair | Should -Be 1
    $Entry.EstimatedSize | Should -BeNullOrEmpty
    $Entry.InstallDate | Should -BeNullOrEmpty
  }

  It 'Should apply post-uninstaller deletion to the built-in ARP entry' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-built-in-arp-delete.exe' -ProjectXml @'
<project>
  <fullName>Deleted Built-In</fullName><version>1.0</version><vendor>Example Vendor</vendor>
  <postUninstallerCreationActionList><registryDelete><key>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Deleted Built-In 1.0</key></registryDelete></postUninstallerCreationActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.WritesBuiltInArp | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.VisibleArpEntries | Should -HaveCount 0
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.ARP.PostCreationDeleteApplied'
  }

  It 'Should promote one surviving custom ARP entry after deleting the built-in entry' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-custom-arp-replacement.exe' -ProjectXml @'
<project>
  <fullName>Replaced Built-In</fullName><version>1.0</version><vendor>Example Vendor</vendor>
  <readyToInstallActionList><registrySet><key>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Product</key><name>DisplayName</name><value>Custom Product</value></registrySet></readyToInstallActionList>
  <postUninstallerCreationActionList><registryDelete><key>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Replaced Built-In 1.0</key></registryDelete></postUninstallerCreationActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.ProductCode | Should -Be 'Custom.Product'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.VisibleArpEntries | Should -HaveCount 1
    $Info.AppsAndFeaturesEntries.ProductCode | Should -Be 'Custom.Product'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.ARP.PostCreationDeleteApplied'
  }

  It 'Should resolve deterministic project identity expressions and omit unresolved identity values' {
    $ResolvedFixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-resolved-identity.exe' -ProjectXml @'
<project>
  <shortName>Identity</shortName><fullName>${project.shortName} Product</fullName><version>2.4</version><vendor>Example Vendor</vendor>
</project>
'@
    $UnresolvedFixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-unresolved-identity.exe' -ProjectXml @'
<project>
  <shortName>Identity</shortName><fullName>${runtime_product_name}</fullName><version>${runtime_version}</version><vendor>${runtime_vendor}</vendor>
  <windowsARPRegistryPrefix>Static.Product</windowsARPRegistryPrefix>
</project>
'@

    $Resolved = Get-InstallBuilderInfo -Path $ResolvedFixture
    $Resolved.DisplayName | Should -Be 'Identity Product'
    $Resolved.ProductCode | Should -Be 'Identity Product 2.4'
    $Resolved.AppsAndFeaturesEntries.DisplayName | Should -Be 'Identity Product'

    $Unresolved = Get-InstallBuilderInfo -Path $UnresolvedFixture
    $Unresolved.DisplayName | Should -BeNullOrEmpty
    $Unresolved.DisplayVersion | Should -BeNullOrEmpty
    $Unresolved.Publisher | Should -BeNullOrEmpty
    $Unresolved.ProductCode | Should -Be 'Static.Product'
    $Unresolved.UnresolvedFields | Should -Contain 'DisplayName'
    $Unresolved.UnresolvedFields | Should -Contain 'DisplayVersion'
    $Unresolved.UnresolvedFields | Should -Contain 'Publisher'
    $Unresolved.UnresolvedFields | Should -Contain 'AppsAndFeaturesEntries'
    $Unresolved.Diagnostics.Id | Should -Contain 'InstallBuilder.Metadata.IdentityUnresolved'
    $Unresolved.Diagnostics.Id | Should -Contain 'InstallBuilder.ARP.BuiltInValuesUnresolved'
  }

  It 'Should make built-in ARP evidence unresolved after a conditional post-creation delete' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-built-in-arp-conditional-delete.exe' -ProjectXml @'
<project>
  <fullName>Conditional Built-In</fullName><version>1.0</version><vendor>Example Vendor</vendor>
  <postUninstallerCreationActionList><registryDelete><key>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Conditional Built-In 1.0</key><ruleList><fileExists><path>${installdir}/marker</path></fileExists></ruleList></registryDelete></postUninstallerCreationActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.UncertainArpEntries.ProductCode | Should -Be 'Conditional Built-In 1.0'
    $Info.UnresolvedFields | Should -Contain 'ProductCode'
    $Info.UnresolvedFields | Should -Contain 'AppsAndFeaturesEntries'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.ARP.PostCreationDeleteConditional'
  }

  It 'Should honor inherited conditions on registry actions' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-conditional-registry.exe' -ProjectXml @'
<project>
  <createWindowsARPEntry>0</createWindowsARPEntry><requestedExecutionLevel>asInvoker</requestedExecutionLevel>
  <readyToInstallActionList>
    <actionGroup><actionList><registrySet><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Static.Product</key><name>DisplayName</name><value>Static Product</value></registrySet></actionList><ruleList><isFalse><value>0</value></isFalse></ruleList></actionGroup>
    <actionGroup><actionList><registrySet><key>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Conditional.Product</key><name>DisplayName</name><value>Conditional Product</value></registrySet></actionList><ruleList><isFalse><value>${installer_is_root_install}</value></isFalse></ruleList></actionGroup>
  </readyToInstallActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    ($Info.RegistryWrites | Where-Object { $_.RawKey -like '*Static.Product' }).ConditionState | Should -Be 'True'
    ($Info.RegistryWrites | Where-Object { $_.RawKey -like '*Conditional.Product' }).ConditionState | Should -Be 'Unknown'
    ($Info.ProjectActions | Where-Object ActionType -EQ 'registrySet') | Should -HaveCount 2
    $Info.ProductCode | Should -Be 'Static.Product'
    $Info.AppsAndFeaturesEntries.ProductCode | Should -Be 'Static.Product'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Registry.ConditionsUnresolved'
    $Info.UnresolvedFields | Should -Contain 'AppsAndFeaturesEntries'
    $Info.UnresolvedFields | Should -Contain 'ProductCode'
  }

  It 'Should not mark manifest registry fields unresolved for an unrelated computed value' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-unrelated-registry.exe' -ProjectXml @'
<project>
  <fullName>Registry Product</fullName><version>1.0</version><vendor>Example Vendor</vendor>
  <readyToInstallActionList><registrySet><key>HKEY_LOCAL_MACHINE\Software\Example\Product</key><name>ConfiguredValue</name><value>${runtime_value}</value></registrySet></readyToInstallActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Registry.ValuesUnresolved'
    ($Info.Diagnostics | Where-Object Id -EQ 'InstallBuilder.Registry.ValuesUnresolved').AffectedFields | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
    $Info.UnresolvedFields | Should -Not -Contain 'AppsAndFeaturesEntries'
    $Info.UnresolvedFields | Should -Not -Contain 'Protocols'
    $Info.UnresolvedFields | Should -Not -Contain 'FileExtensions'
  }

  It 'Should exclude non-installation registry phases from ARP and association projection' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-registry-phases.exe' -ProjectXml @'
<project>
  <fullName>Phase Product</fullName><version>1.0</version><vendor>Example Vendor</vendor>
  <createWindowsARPEntry>0</createWindowsARPEntry><requestedExecutionLevel>asInvoker</requestedExecutionLevel>
  <parameterList><directoryParameter><name>installdir</name><value>C:\Apps\Phase</value></directoryParameter></parameterList>
  <initializationActionList><setInstallerVariable name="custom.product" value="${project.fullName}" /></initializationActionList>
  <preInstallationActionList>
    <registrySet><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Installed.Product</key><name>DisplayName</name><value>Installed Product</value></registrySet>
    <registrySet><key>HKEY_CURRENT_USER\Software\Classes\.installed</key><name></name><value>Installed.Product</value></registrySet>
    <registrySet><key>HKEY_CURRENT_USER\Software\Classes\Installed.Product\shell\open\command</key><name></name><value>&quot;${installdir}\app.exe&quot; &quot;%1&quot;</value></registrySet>
  </preInstallationActionList>
  <preUninstallationActionList>
    <registrySet><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Removed.Product</key><name>DisplayName</name><value>Removed Product</value></registrySet>
    <registrySet><key>HKEY_CURRENT_USER\Software\Classes\.removed</key><name></name><value>Removed.Product</value></registrySet>
  </preUninstallationActionList>
  <finalPageActionList><registrySet><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\UiOnly.Product</key><name>DisplayName</name><value>UI Product</value></registrySet></finalPageActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.RegistryWrites | Should -HaveCount 6
    ($Info.RegistryWrites | Where-Object Lifecycle -EQ 'Installation').Count | Should -Be 3
    ($Info.RegistryWrites | Where-Object Lifecycle -EQ 'Uninstallation').Count | Should -Be 2
    ($Info.RegistryWrites | Where-Object Lifecycle -EQ 'Presentation').Count | Should -Be 1
    ($Info.ProjectActions | Where-Object ActionType -EQ 'setInstallerVariable').Properties.name | Should -Be 'custom.product'
    ($Info.ProjectActions | Where-Object ActionType -EQ 'setInstallerVariable').ResolvedProperties.value | Should -Be 'Phase Product'
    $Info.VisibleArpEntries.ProductCode | Should -Be @('Installed.Product')
    $Info.FileExtensions | Should -Contain 'installed'
    $Info.FileExtensions | Should -Not -Contain 'removed'
    ($Info.RegistryAssociationInfo.FileExtensionAssociations | Where-Object Extension -EQ '.installed').Command | Should -Be '"C:\Apps\Phase\app.exe" "%1"'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Registry.NonInstallPhaseExcluded'
  }

  It 'Should apply folder-owned registry sets and later deletes in runtime order' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-registry-delete.exe' -ProjectXml @'
<project>
  <createWindowsARPEntry>0</createWindowsARPEntry><requestedExecutionLevel>asInvoker</requestedExecutionLevel>
  <componentList><component><name>default</name><folderList><folder><name>files</name><destination>C:\Apps\Registry</destination><actionList>
    <registrySet><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Folder.Product</key><name>DisplayName</name><value>Folder Product</value></registrySet>
    <registrySet><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Deleted.Product</key><name>DisplayName</name><value>Deleted Product</value></registrySet>
    <registryDelete><key>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Deleted.Product</key></registryDelete>
    <registrySet><key>HKEY_CURRENT_USER\Software\Classes\.deleted</key><value>Deleted.Document</value></registrySet>
    <registryDelete><key>HKEY_CURRENT_USER\Software\Classes\.deleted</key></registryDelete>
  </actionList></folder></folderList></component></componentList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.RegistryOperations | Should -HaveCount 5
    $Info.RegistryWrites | Should -HaveCount 3
    $Info.RegistryDeletes | Should -HaveCount 2
    $Info.EffectiveRegistryWrites | Should -HaveCount 1
    $Info.EffectiveRegistryWrites[0].Phase | Should -Be 'folderActionList'
    $Info.EffectiveRegistryWrites[0].Lifecycle | Should -Be 'Installation'
    $Info.ProductCode | Should -Be 'Folder.Product'
    $Info.VisibleArpEntries.ProductCode | Should -Not -Contain 'Deleted.Product'
    $Info.FileExtensions | Should -Not -Contain 'deleted'
  }

  It 'Should apply native file-association removal actions without losing operation evidence' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-association-remove.exe' -ProjectXml @'
<project>
  <readyToInstallActionList>
    <associateWindowsFileExtension><extensions>.kept .removed</extensions><progID>Example.Document</progID></associateWindowsFileExtension>
    <removeWindowsFileAssociation><extensions>.removed</extensions><progID>Example.Document</progID></removeWindowsFileAssociation>
  </readyToInstallActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.FileExtensions | Should -Be @('kept')
    $Info.FileExtensionAssociations | Should -HaveCount 3
    ($Info.FileExtensionAssociations | Where-Object Operation -EQ 'Remove').Extension | Should -Be '.removed'
    $Info.AssociationInfo.ActionAssociations | Should -HaveCount 3
  }

  It 'Should expose declarative .NET Framework detection ranges as runtime requirements' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-dotnet.exe' -ProjectXml @'
<project>
  <preInstallationActionList><autodetectDotNetFramework><validDotNetVersionList><validDotNetVersion><minVersion>4.7.2</minVersion><maxVersion>4.8.1</maxVersion></validDotNetVersion></validDotNetVersionList></autodetectDotNetFramework></preInstallationActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.RuntimeRequirements.DotNetFramework | Should -HaveCount 1
    $Info.RuntimeRequirements.DotNetFramework[0].ValidVersions[0].MinimumVersion | Should -Be '4.7.2'
    $Info.RuntimeRequirements.DotNetFramework[0].ValidVersions[0].MaximumVersion | Should -Be '4.8.1'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Requirement.DotNetFramework'
  }

  It 'Should evaluate the documented portable InstallBuilder rule subset' {
    $Variables = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Variables['known'] = 'AlphaBeta'
    $Context = [pscustomobject]@{ Variables = $Variables; IsNative64Bit = $true; NativePlatform = 'windows-x64' }
    $Cases = @(
      [pscustomobject]@{ Xml = '<compareText text="${known}" value="beta" logic="contains" nocase="1" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<compareText text="same" value="same" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<compareText text="AlphaBeta" value="gamma" logic="does_not_contain" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<compareTextLength text="abcd" length="3" logic="greater" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<compareValues value1="10" value2="2" logic="greater" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<compareValues value1="beta" value2="alpha" logic="greater" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<isTrue value="anything-else" />'; Expected = 'False' },
      [pscustomobject]@{ Xml = '<isFalse value="anything-else" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<platformTest type="linux-x64" />'; Expected = 'False' },
      [pscustomobject]@{ Xml = '<regExMatch text="release-42" pattern="^release-[0-9]+$" logic="matches" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<regExMatch text="release-42" pattern="^release-[0-9]+$" />'; Expected = 'True' },
      [pscustomobject]@{ Xml = '<regExMatch text="release-42" pattern="[[:digit:]]+" logic="matches" />'; Expected = 'Unknown' }
    )

    foreach ($Case in $Cases) {
      $State = & (Get-Module InstallBuilder) { param($RuleXml, $Context) [xml]$Document = "<root>$RuleXml</root>"; Resolve-InstallBuilderRuleState -Rule $Document.DocumentElement.FirstChild -Context $Context } $Case.Xml $Context
      $State.State | Should -Be $Case.Expected -Because $Case.Xml
    }

    [xml]$LegacyRuleList = '<owner><ruleLogic>or</ruleLogic><ruleList><isTrue value="0" /><isTrue value="yes" /></ruleList></owner>'
    $LegacyState = & (Get-Module InstallBuilder) { param($Owner, $Context) Resolve-InstallBuilderRuleList -RuleList $Owner.SelectSingleNode('ruleList') -Owner $Owner -Context $Context } $LegacyRuleList.DocumentElement $Context
    $LegacyState.State | Should -Be 'True'
  }

  It 'Should resolve stable InstallBuilder Windows folders without using host-specific paths' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-folders.exe' -ProjectXml @'
<project>
  <shortName>Folders</shortName><fullName>Folder Product</fullName><version>1.0</version>
  <parameterList><directoryParameter><name>installdir</name><value>${windows_folder_common_documents}/Folder Product</value></directoryParameter></parameterList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture
    $Context = & (Get-Module InstallBuilder) { param([string]$Path) $Project = Get-InstallBuilderProjectData -Path $Path; [xml]$Xml = $Project.Content; Get-InstallBuilderProjectContext -Xml $Xml -Path $Path } $Fixture

    $Info.DefaultInstallLocation | Should -Be '%PUBLIC%\Documents\Folder Product'
    $Context.Variables['windows_folder_systemroot'] | Should -Be '%SystemRoot%'
    $Context.Variables['windows_folder_startup'] | Should -Be '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'
    $Context.Variables['windows_folder_common_programs'] | Should -Be '%ProgramData%\Microsoft\Windows\Start Menu\Programs'
    $Context.Variables['windows_folder_profile'] | Should -Be '%USERPROFILE%'
    $Context.Variables['windows_folder_common_video'] | Should -Be '%PUBLIC%\Videos'
    $Context.Variables.ContainsKey('windows_folder_internet_cache') | Should -BeFalse
  }

  It 'Should project documented persistent Windows system effects' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-system-effects.exe' -ProjectXml @'
<project>
  <shortName>Effects</shortName><fullName>Effects Product</fullName><version>1.0</version><vendor>Example Vendor</vendor>
  <requestedExecutionLevel>requireAdministrator</requestedExecutionLevel>
  <parameterList><directoryParameter><name>installdir</name><value>${windows_folder_program_files}/Effects</value></directoryParameter></parameterList>
  <readyToInstallActionList>
    <associateWindowsFileExtension>
      <extensions>.sample sample2</extensions><progID>Effects.Document</progID><icon>${installdir}/effects.exe,0</icon><scope>user</scope><mimeType>application/x-effects</mimeType><friendlyName>Effects document</friendlyName>
      <commandList><command><verb>open</verb><runProgram>${installdir}/effects.exe</runProgram><runProgramArguments>&quot;%1&quot;</runProgramArguments></command></commandList>
    </associateWindowsFileExtension>
    <associateWindowsFileExtension><extensions>.dynamic</extensions><progID>Effects.Dynamic</progID><commandList><command><verb>open</verb><runProgram>${runtime_program}</runProgram></command></commandList></associateWindowsFileExtension>
    <associateWindowsFileExtension><extensions>.conditional</extensions><progID>Effects.Conditional</progID><ruleList><fileExists><path>${installdir}/optional.flag</path></fileExists></ruleList></associateWindowsFileExtension>
    <addDirectoryToPath><path>${installdir}/bin</path><scope>user</scope><insertAt>beginning</insertAt></addDirectoryToPath>
    <addEnvironmentVariable><name>EFFECTS_HOME</name><value>${installdir}</value><scope>system</scope></addEnvironmentVariable>
    <setEnvironmentVariable><name>EFFECTS_TRANSIENT</name><value>1</value></setEnvironmentVariable>
    <addScheduledTask><name>Effects Daily</name><program>${installdir}/effects.exe</program><programArguments>--scheduled</programArguments><workingDirectory>${installdir}</workingDirectory><runAsAdmin>1</runAsAdmin><password>secret-value-must-not-be-returned</password></addScheduledTask>
    <addFonts><files>${installdir}/fonts/*.ttf</files></addFonts>
    <addSharedDLL><path>${installdir}/effects-shared.dll</path></addSharedDLL>
    <setWindowsACL><files>${installdir}/data</files><users>S-1-5-32-545</users><permissions>generic_read</permissions><action>allow</action><recurseObjects>1</recurseObjects></setWindowsACL>
    <createWindowsService><serviceName>EffectsService</serviceName><displayName>Effects Service</displayName><program>${installdir}/service.exe</program><programArguments>--service</programArguments><startType>auto</startType><dependencies>RpcSs, EventLog</dependencies><password>secret-value-must-not-be-returned</password></createWindowsService>
    <startWindowsService><serviceName>EffectsService</serviceName></startWindowsService>
  </readyToInstallActionList>
  <preUninstallationActionList><associateWindowsFileExtension><extensions>.removed</extensions><progID>Removed.Document</progID></associateWindowsFileExtension></preUninstallationActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Effects'
    $Info.FileExtensions | Should -Be @('dynamic', 'sample', 'sample2')
    $Info.FileExtensions | Should -Not -Contain 'conditional'
    $Info.FileExtensions | Should -Not -Contain 'removed'
    $Info.FileExtensionAssociations | Should -HaveCount 5
    $Association = $Info.FileExtensionAssociations | Where-Object Extension -EQ '.sample'
    $Association.DefaultProgId | Should -Be 'Effects.Document'
    $Association.Scope | Should -Be 'user'
    $Association.Command | Should -Be '"%ProgramFiles(x86)%\Effects\effects.exe" "%1"'
    $Association.DefaultIcon | Should -Be '%ProgramFiles(x86)%\Effects\effects.exe,0'
    $Info.PathChanges | Should -HaveCount 1
    $Info.PathChanges[0].Path | Should -Be '%ProgramFiles(x86)%\Effects\bin'
    $Info.PathChanges[0].AppliesToInstalledState | Should -BeTrue
    $Info.EnvironmentChanges | Should -HaveCount 2
    ($Info.EnvironmentChanges | Where-Object Name -EQ 'EFFECTS_HOME').Persistent | Should -BeTrue
    ($Info.EnvironmentChanges | Where-Object Name -EQ 'EFFECTS_TRANSIENT').AppliesToInstalledState | Should -BeFalse
    $Info.WindowsServices | Should -HaveCount 2
    $Info.WindowsServices[0].ServiceName | Should -Be 'EffectsService'
    $Info.WindowsServices[0].Dependencies | Should -Be @('RpcSs', 'EventLog')
    $Info.WindowsServices[0].StartType | Should -Be 'auto'
    $Info.WindowsServices[0].Account | Should -Be 'LocalSystem'
    $Info.WindowsServices[0].AbortOnError | Should -BeFalse
    $Info.WindowsServices[0].PasswordConfigured | Should -BeTrue
    $Info.WindowsServices[0].PSObject.Properties.Name | Should -Not -Contain 'Password'
    $Info.WindowsServices[1].Operation | Should -Be 'Start'
    $Info.WindowsServices[1].DelayMilliseconds | Should -Be 15000
    $Info.ScheduledTasks | Should -HaveCount 1
    $Info.ScheduledTasks[0].Operation | Should -Be 'CreateOrUpdate'
    $Info.ScheduledTasks[0].TriggerType | Should -Be 'DAILY'
    $Info.ScheduledTasks[0].Program | Should -Be '%ProgramFiles(x86)%\Effects\effects.exe'
    $Info.ScheduledTasks[0].RunAsAdministrator | Should -BeTrue
    $Info.ScheduledTasks[0].PasswordConfigured | Should -BeTrue
    $Info.ScheduledTasks[0].PSObject.Properties.Name | Should -Not -Contain 'Password'
    $Info.FontChanges | Should -HaveCount 1
    $Info.FontChanges[0].Operation | Should -Be 'Add'
    $Info.FontChanges[0].Files | Should -Be '%ProgramFiles(x86)%\Effects\fonts\*.ttf'
    $Info.SharedDllChanges | Should -HaveCount 1
    $Info.SharedDllChanges[0].Operation | Should -Be 'IncrementReference'
    $Info.SharedDllChanges[0].Path | Should -Be '%ProgramFiles(x86)%\Effects\effects-shared.dll'
    $Info.WindowsAclChanges | Should -HaveCount 1
    $Info.WindowsAclChanges[0].Operation | Should -Be 'Set'
    $Info.WindowsAclChanges[0].Permissions | Should -Be 'generic_read'
    $Info.WindowsAclChanges[0].RecurseObjects | Should -BeTrue
    ($Info.ProjectActions | Where-Object ActionType -EQ 'createWindowsService').Properties.password | Should -Be '<redacted>'
    ($Info.ProjectActions | Where-Object ActionType -EQ 'createWindowsService').SensitiveProperties | Should -Contain 'password'
    ($Info | ConvertTo-Json -Depth 20) | Should -Not -Match 'secret-value-must-not-be-returned'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Association.ConditionsUnresolved'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Association.ValuesUnresolved'
  }

  It 'Should expose unresolved project logic with exact source and referenced variable values' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-dynamic-logic.exe' -ProjectXml @'
<project>
  <shortName>Dynamic</shortName><version>1.0</version>
  <parameterList>
    <directoryParameter><name>installdir</name><value>C:\Apps\Dynamic</value></directoryParameter>
    <stringParameter><name>channel</name><value>beta</value></stringParameter>
    <passwordParameter><name>apiToken</name><value>do-not-return-this-secret</value></passwordParameter>
  </parameterList>
  <postInstallationScript>${installdir}/post-install.cmd</postInstallationScript>
  <readyToInstallActionList>
    <runProgram>
      <program>${installdir}/app.exe</program><programArguments>--channel ${channel} --state ${runtime_state}</programArguments>
      <ruleList><fileExists><path>${runtime_state}/enabled.flag</path></fileExists></ruleList>
    </runProgram>
  </readyToInstallActionList>
  <finalPageActionList>
    <runProgram>
      <program>${installdir}/app.exe</program>
      <ruleList><fileExists><path>${runtime_state}/launch.flag</path></fileExists></ruleList>
    </runProgram>
  </finalPageActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Rule = @($Info.DynamicProjectLogic | Where-Object { $_.EvidenceKind -eq 'Rule' -and $_.OwnerType -eq 'runProgram' -and $_.Phase -eq 'readyToInstallActionList' })
    $Rule | Should -HaveCount 1
    $Rule[0].SourceCode | Should -Match '<fileExists>'
    $Rule[0].ReferencedVariables | Should -Contain 'runtime_state'
    ($Rule[0].VariableValues | Where-Object Name -EQ 'runtime_state').Source | Should -Be 'RuntimeOrUnknown'
    $Rule[0].AffectedFields | Should -Contain 'ProductCode'

    $PresentationRule = @($Info.DynamicProjectLogic | Where-Object { $_.EvidenceKind -eq 'Rule' -and $_.OwnerType -eq 'runProgram' -and $_.Phase -eq 'finalPageActionList' })
    $PresentationRule | Should -HaveCount 1
    $PresentationRule[0].AffectedFields | Should -BeNullOrEmpty

    $Expression = @($Info.DynamicProjectLogic | Where-Object { $_.EvidenceKind -eq 'Expression' -and $_.Property -eq 'programArguments' })
    $Expression | Should -HaveCount 1
    $Expression[0].SourceCode | Should -Be '--channel ${channel} --state ${runtime_state}'
    ($Expression[0].VariableValues | Where-Object Name -EQ 'channel').Value | Should -Be 'beta'
    ($Expression[0].VariableValues | Where-Object Name -EQ 'channel').IsRuntimeMutable | Should -BeTrue

    $ScriptReference = @($Info.DynamicProjectLogic | Where-Object { $_.EvidenceKind -eq 'ScriptOrExpression' -and $_.Property -eq 'postInstallationScript' })
    $ScriptReference | Should -HaveCount 1
    $ScriptReference[0].SourceCode | Should -Be '${installdir}/post-install.cmd'
    ($Info | ConvertTo-Json -Depth 20) | Should -Not -Match 'do-not-return-this-secret'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Project.DynamicLogic'
  }

  It 'Should honor explicit installation-mode allowlists and legacy UI capabilities' {
    $LegacyUnattended = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-unattended-only.exe' -ProjectXml '<project><shortName>Modes</shortName><version>1.0</version><allowedInstallationModes>unattended</allowedInstallationModes></project>'
    $ModernUnattended = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-modern-unattended-only.exe' -ProjectXml '<project><shortName>Modes</shortName><version>1.0</version><allowedInstallationModes>unattended</allowedInstallationModes><unattendedModeUI>minimal</unattendedModeUI></project>'
    $InteractiveOnly = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-interactive-only.exe' -ProjectXml '<project><shortName>Modes</shortName><version>1.0</version><allowedInstallationModes>win32</allowedInstallationModes></project>'

    $LegacyInfo = Get-InstallBuilderInfo -Path $LegacyUnattended
    $LegacyInfo.InstallModes | Should -Be @('silent')
    $LegacyInfo.InstallerSwitches.Silent | Should -Be '--mode unattended'
    $LegacyInfo.InstallerSwitches.SilentWithProgress | Should -Be '--mode unattended'

    $ModernInfo = Get-InstallBuilderInfo -Path $ModernUnattended
    $ModernInfo.InstallModes | Should -Be @('silent', 'silentWithProgress')
    $ModernInfo.InstallerSwitches.Silent | Should -Be '--mode unattended --unattendedmodeui none'
    $ModernInfo.InstallerSwitches.SilentWithProgress | Should -Be '--mode unattended --unattendedmodeui minimal'

    $InteractiveInfo = Get-InstallBuilderInfo -Path $InteractiveOnly
    $InteractiveInfo.InstallModes | Should -Be @('interactive')
    $InteractiveInfo.SupportsSilentInstallation | Should -BeFalse
    $InteractiveInfo.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Silent'
  }

  It 'Should export project.xml through the bounded extractor when no CookFS payload is present' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-expand.exe' -ProjectXml '<project><shortName>Expand</shortName><version>2.0</version></project>'
    $Destination = Join-Path $Script:FixtureDirectory 'expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -CollisionAction Rename
      $Extracted | Should -HaveCount 1
      $Extracted[0].Name | Should -Be 'project.xml'
      (Get-Content -LiteralPath $Extracted[0].FullName -Raw) | Should -Match '<shortName>Expand</shortName>'
      { Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name '*.exe' -CollisionAction Rename } | Should -Throw '*CFS0002*'
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reconstruct logical files from an unencrypted CookFS payload' {
    $Fixture = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-cookfs.exe' -ProjectXml '<project><shortName>Cookfs</shortName><version>1.0</version></project>'
    $Destination = Join-Path $Script:FixtureDirectory 'cookfs-expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallBuilderInfo -Path $Fixture
      $Info.PayloadFiles | Should -BeNullOrEmpty
      $Info.PackagedPayloadFiles | Should -Contain 'app.exe'
      $Info.PackagedPayloadFiles | Should -Contain 'readme.txt'
      $Info.PackagedPayloadFiles | Should -Not -Contain 'app.exe___bitrockBigFile1'
      $Info.ConditionalPayloadFiles | Should -Contain 'app.exe'
      $Info.UnresolvedFields | Should -Contain 'PayloadFiles'
      $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Payload.ConditionsUnresolved'
      $Info.CookfsInfo.CompressionTypes | Should -Be @('None')

      $Extracted = Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name 'app.exe' -CollisionAction Rename
      $Extracted | Should -HaveCount 1
      $Extracted[0].Name | Should -Be 'app.exe'
      [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Extracted[0].FullName)) | Should -Be 'first-second'
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should honor component selection when projecting the default payload' {
    [xml]$Project = @'
<project>
  <shortName>Selection</shortName><version>1.0</version>
  <parameterList><directoryParameter><name>installdir</name><value>C:\Apps\Selection</value></directoryParameter></parameterList>
  <componentList><component><name>optional</name><selected>0</selected><folderList><folder><name>files</name><destination>${installdir}</destination><platforms>windows</platforms></folder></folderList></component></componentList>
</project>
'@
    $Variables = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Variables['installdir'] = 'C:\Apps\Selection'
    $Context = [pscustomobject]@{ Variables = $Variables; InstallLocation = 'C:\Apps\Selection'; NativePlatform = 'windows-x64'; IsNative64Bit = $true }

    $Map = & (Get-Module InstallBuilder) { param([xml]$Xml, $Context) Get-InstallBuilderFolderDestinationMap -Xml $Xml -Context $Context } $Project $Context
    $Entry = $Map['optional/files']

    $Entry.Prefix | Should -Be ''
    $Entry.ConditionState | Should -Be 'False'
    $Entry.Conditions.Type | Should -Contain 'ComponentSelected'
    $Entry.Conditions.Type | Should -Contain 'PlatformList'
  }

  It 'Should decode the InstallBuilder BZip2 CookFS record framing' {
    $Fixture = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-bzip2.exe' -ProjectXml '<project><shortName>BZip2</shortName><version>1.0</version></project>' -Compression BZip2
    $Destination = Join-Path $Script:FixtureDirectory 'bzip2-expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallBuilderInfo -Path $Fixture
      $Info.CookfsInfo.CompressionTypes | Should -Be @('BZip2')

      $Extracted = @(Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name 'app.exe' -CollisionAction Rename)
      $Extracted | Should -HaveCount 1
      [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Extracted[0].FullName)) | Should -Be 'first-second'
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should decode CookFS timestamps and validate MD5 and CRC32 page hashes' {
    foreach ($HashAlgorithm in 'md5', 'crc32') {
      $Fixture = New-TestCookfsInstallBuilderFixture -Name "synthetic-installbuilder-$HashAlgorithm-hash.exe" -ProjectXml '<project><shortName>Hash</shortName><version>1.0</version></project>' -PageHashAlgorithm $HashAlgorithm
      $Destination = Join-Path $Script:FixtureDirectory "$HashAlgorithm-hash-expanded"
      try {
        $Info = Get-InstallBuilderInfo -Path $Fixture
        $Info.CookfsInfo.PageHashAlgorithm | Should -Be $HashAlgorithm
        $Info.CookfsInfo.IndexMetadata.Key | Should -Contain 'cookfs.pagehash'
        $Entry = $Info.PayloadCatalog | Where-Object PhysicalPath -CEQ 'app.exe' | Select-Object -First 1
        $Entry.ModificationTimeUnixSeconds | Should -Be 1700000000
        $Entry.ModificationTimeUtc | Should -Be ([DateTimeOffset]::FromUnixTimeSeconds(1700000000).UtcDateTime)

        $Extracted = @(Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name 'app.exe' -CollisionAction Rename)
        $Extracted | Should -HaveCount 1
        $Extracted[0].LastWriteTimeUtc | Should -Be ([DateTimeOffset]::FromUnixTimeSeconds(1700000000).UtcDateTime)
      } finally {
        Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Should reject a CookFS payload whose page hash does not match its expanded bytes' {
    $Fixture = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-corrupt-hash.exe' -ProjectXml '<project><shortName>Corrupt</shortName><version>1.0</version></project>' -CorruptPageHash
    $Destination = Join-Path $Script:FixtureDirectory 'corrupt-hash-expanded'
    try {
      { Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name 'app.exe' -CollisionAction Rename } | Should -Throw '*failed its MD5 integrity check*'
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should catalog embedded installer-like executions separately from final-page launches' {
    $Fixture = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-execution.exe' -ProjectXml @'
<project>
  <shortName>Execution</shortName><version>1.0</version><requestedExecutionLevel>asInvoker</requestedExecutionLevel>
  <parameterList><directoryParameter><name>installdir</name><value>C:\Apps\Execution</value></directoryParameter></parameterList>
  <preInstallationActionList><runProgram><program>${installdir}/app.exe</program><programArguments>/quiet</programArguments></runProgram></preInstallationActionList>
  <finalPageActionList><runProgram><program>${installdir}/app.exe</program></runProgram></finalPageActionList>
</project>
'@

    $Info = Get-InstallBuilderInfo -Path $Fixture

    $Info.ExecutionActions | Should -HaveCount 2
    ($Info.ProjectActions | Where-Object ActionType -EQ 'runProgram') | Should -HaveCount 2
    $Info.ExecutedPayloads | Should -Be @('app.exe')
    $Info.PrimaryExecutableCandidates | Should -Be @('app.exe')
    $Info.NestedInstallerCandidates | Should -HaveCount 1
    $Info.NestedInstallerCandidates[0].Phase | Should -Be 'preInstallationActionList'
    $Info.Diagnostics.Id | Should -Contain 'InstallBuilder.Execution.NestedInstallerCandidates'
  }

  It 'Should reject unsupported CookFS custom compression before payload extraction' {
    $Fixture = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-unsupported-cookfs.exe' -ProjectXml '<project><shortName>Unsupported</shortName><version>1.0</version></project>' -UnsupportedCookfsCompression
    $Destination = Join-Path $Script:FixtureDirectory 'unsupported-cookfs-expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallBuilderInfo -Path $Fixture
      $Info.CookfsInfo.HasUnsupportedCompression | Should -BeTrue
      $Info.Diagnostics.Message | Should -Contain 'The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password.'
      { Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name 'app.exe' -CollisionAction Rename } | Should -Throw '*unsupported custom or encrypted compression*'
      Test-Path -LiteralPath (Join-Path $Destination 'app.exe') | Should -BeFalse
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should surface InstallBuilder metadata in the static installer analyzer' {
    $Fixture = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-analyzer.exe' -ProjectXml '<project><shortName>Analyzer</shortName><fullName>Analyzer Product</fullName><version>3.0</version><vendor>Example Vendor</vendor><requireInstallationByRootUser>1</requireInstallationByRootUser></project>'
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Index.ps1') -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $Fixture
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'InstallBuilder' } | Select-Object -First 1

    $Result.Success | Should -BeTrue
    $Result.Result.ProductName | Should -Be 'Analyzer Product'
    $Result.Result.ProductCode | Should -Be 'Analyzer Product 3.0'
    $Result.Result.Scope | Should -Be 'machine'
  }

  It 'Should reject a project marker without a valid PE and structured container' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-marker-only.exe' -ProjectXml '<project><shortName>Marker</shortName><version>1.0</version></project>'
    Test-InstallBuilder -Path $Fixture | Should -BeFalse
  }

  It 'Should reconstruct documented defaults from the current official x64 installer' {
    $Info = Get-InstallBuilderInfo -Path $Script:InstallBuilderCurrentFixture

    $Info.ProductCode | Should -Be 'InstallBuilder for Windows 26.8.0'
    $Info.DisplayName | Should -Be 'InstallBuilder for Windows'
    $Info.DisplayVersion | Should -Be '26.8.0'
    $Info.Publisher | Should -Be 'Backstaff'
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryView | Should -Be '64-bit'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\installbuilder-26.8.0'
    $Info.RequestedExecutionLevel | Should -Be 'requireAdministrator'
    $Info.ElevationRequirement | Should -Be 'elevatesSelf'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.WritesBuiltInArp | Should -BeTrue
    $Info.VisibleArpEntries[0].UninstallString | Should -Be '"%ProgramFiles%\installbuilder-26.8.0\uninstall.exe"'
    $Info.VisibleArpEntries[0].DisplayIcon | Should -Be '%ProgramFiles%\installbuilder-26.8.0/uninstall.exe'
    $Info.VisibleArpEntries[0].UrlInfoAbout | Should -Be 'http://installbuilder.com'
    $Info.VisibleArpEntries[0].HelpLink | Should -Be 'http://installbuilder.com/support.html'
    $Info.VisibleArpEntries[0].SystemComponent | Should -BeNullOrEmpty
    $Info.VisibleArpEntries[0].NoModify | Should -Be 1
    $Info.VisibleArpEntries[0].NoRepair | Should -Be 1
    $Info.PayloadFileCount | Should -BeGreaterThan 0
    $Info.PayloadFiles | Should -Contain 'bin/builder.exe'
    $Info.PrimaryExecutableCandidates | Should -Contain 'bin/builder.exe'
    ($Info.Shortcuts | Where-Object PayloadPath -EQ 'bin/builder.exe').IsEmbeddedPayload | Should -Contain $true
    $Info.PayloadFiles | Should -Not -Contain 'builder/executables/bin/builder.exe'
    ($Info.PayloadCatalog | Where-Object Path -CEQ 'bin/builder.exe').PhysicalPath | Should -Be 'builder/executables/bin/builder.exe'
    $Info.CookfsInfo.CompressionTypes | Should -Contain 'Lzma'
    $Info.InstallerSwitches.InstallLocation | Should -Be '--prefix "<INSTALLPATH>"'
  }

  It 'Should extract a current CookFS file at its compiled destination path' {
    $Destination = Join-Path $Script:FixtureDirectory 'current-cookfs-expanded'
    try {
      $Extracted = @(Expand-InstallBuilderInstaller -Path $Script:InstallBuilderCurrentFixture -DestinationPath $Destination -Name 'bin/logo.png' -CollisionAction Rename)

      $Extracted | Should -HaveCount 1
      $Extracted[0].FullName | Should -Be (Join-Path $Destination 'bin\logo.png')
      $Extracted[0].Length | Should -BeGreaterThan 0
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract byte-exact files from distinct real Deflate and historical LZMA routes' {
    $Cases = @(
      [pscustomobject]@{ Path = $Script:InstallBuilderDeflateFixture; Name = 'language/test/fnord.txt'; Length = 46; Sha256 = '2C7228AA6F27693E2C4FDB72666CA6208D7070CB96BEE444A4F0AF225CAF1424' },
      [pscustomobject]@{ Path = $Script:InstallBuilderMultiVfsFixture; Name = 'demo/docs/license.txt'; Length = 15; Sha256 = '0B8F88B94EACB00C34B77BFCE908DDDBC2AA7719FF0AEBA42D01025E206D8429' }
    )
    foreach ($Case in $Cases) {
      $Destination = Join-Path $Script:FixtureDirectory ([IO.Path]::GetRandomFileName())
      try {
        $Extracted = @(Expand-InstallBuilderInstaller -Path $Case.Path -DestinationPath $Destination -Name $Case.Name -CollisionAction Rename)
        $Extracted | Should -HaveCount 1
        $Extracted[0].Length | Should -Be $Case.Length
        (Get-FileHash -LiteralPath $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be $Case.Sha256
      } finally {
        Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Should optionally analyze source-referenced primary payload executables' {
    $Info = Get-InstallBuilderInfo -Path $Script:InstallBuilderCurrentFixture -AnalyzePrimaryExecutables -MaximumPayloadAnalysisBytes 268435456

    $Info.PayloadAnalysisFiles | Should -Contain 'bin/builder.exe'
    $Info.PayloadArchitectureInfo | Should -Not -BeNullOrEmpty
    $Info.PayloadArchitectures | Should -Contain 'x64'
    $Info.PayloadDependencyInfo | Should -Not -BeNullOrEmpty
  }

  It 'Should classify the distinct historical container and runtime generations' {
    $Cases = @(
      [pscustomobject]@{ Path = $Script:InstallBuilderLegacyFixture; Generation = 'LegacyMetakit'; Version = '3.6.0'; Publisher = 'Name of your company'; RegistryView = '32-bit'; Compression = $null },
      [pscustomobject]@{ Path = $Script:InstallBuilderDeflateFixture; Generation = 'CookFS2'; Version = '3.3.1.2'; Publisher = 'JXplorer Open Source Project'; RegistryView = '32-bit'; Compression = 'Deflate' },
      [pscustomobject]@{ Path = $Script:InstallBuilderMultiVfsFixture; Generation = 'CookFS2'; Version = '8.2.0'; Publisher = 'BitRock'; RegistryView = '32-bit'; Compression = 'Lzma' },
      [pscustomobject]@{ Path = $Script:InstallBuilderLzmaFixture; Generation = 'CookFS2'; Version = '9.5.5'; Publisher = 'BitRock'; RegistryView = '32-bit'; Compression = 'Lzma' },
      [pscustomobject]@{ Path = $Script:InstallBuilderRebrandFixture; Generation = 'CookFS2'; Version = '23.1.0'; Publisher = 'Backstaff'; RegistryView = '32-bit'; Compression = 'Lzma' },
      [pscustomobject]@{ Path = $Script:InstallBuilderCurrentFixture; Generation = 'CookFS2'; Version = '26.8.0'; Publisher = 'Backstaff'; RegistryView = '64-bit'; Compression = 'Lzma' }
    )

    foreach ($Case in $Cases) {
      $Info = Get-InstallBuilderInfo -Path $Case.Path
      $Info.FormatGeneration | Should -Be $Case.Generation
      $Info.DisplayVersion | Should -Be $Case.Version
      $Info.Publisher | Should -Be $Case.Publisher
      $Info.RegistryView | Should -Be $Case.RegistryView
      $Info.MetakitLayouts | Should -Not -BeNullOrEmpty
      if ($Case.Compression) { $Info.CookfsInfo.CompressionTypes | Should -Contain $Case.Compression }
    }

    $LegacyInfo = Get-InstallBuilderInfo -Path $Script:InstallBuilderLegacyFixture
    $LegacyInfo.ProjectSchemaVersion | Should -Be '1.2'
    $LegacyInfo.PayloadFileCount | Should -Be 88
    $LegacyInfo.PayloadCatalog | Should -HaveCount 88
    $LegacyInfo.PayloadFiles | Should -Contain 'bin/builder.exe'
    $LegacyInfo.PayloadFiles | Should -Contain 'demo/docs/license.txt'
    $LegacyInfo.ExtractedFiles | Should -Contain 'project.xml'
    $LegacyInfo.ExtractedFiles | Should -Contain 'bin/builder.exe'
    ($LegacyInfo.PayloadCatalog | Where-Object Path -CEQ 'bin/builder.exe').PhysicalPath | Should -Be 'dist/builder/executables/bin/builder.exe'
    $LegacyInfo.MetakitInfo.EntryCount | Should -Be 317
    $LegacyInfo.MetakitInfo.OriginDirectory | Should -Be 'dist'
    $LegacyInfo.MetakitInfo.CompressionTypes | Should -Contain 'None'
    $LegacyInfo.MetakitInfo.CompressionTypes | Should -Contain 'Zlib'
    $LegacyInfo.Diagnostics.Id | Should -Not -Contain 'InstallBuilder.Payload.LegacyMetakitUnsupported'
    $LegacyInfo.UnresolvedFields | Should -Not -Contain 'PayloadFiles'

    $DeflateInfo = Get-InstallBuilderInfo -Path $Script:InstallBuilderDeflateFixture
    $DeflateInfo.CookfsInfo.CompressionTypes | Should -Contain 'None'
    $DeflateInfo.PayloadFileCount | Should -Be 189
    $DeflateInfo.RuntimeRequirements.Java | Should -HaveCount 1
    $DeflateInfo.RuntimeRequirements.Java[0].ValidVersions[0].MinimumVersion | Should -Be '1.5.0'
    $DeflateInfo.RuntimeRequirements.Java[0].ValidVersions[0].RequireJdk | Should -BeFalse
    $DeflateInfo.Diagnostics.Id | Should -Contain 'InstallBuilder.Requirement.Java'

    $MultiVfsInfo = Get-InstallBuilderInfo -Path $Script:InstallBuilderMultiVfsFixture
    $MultiVfsInfo.MetakitLayouts | Should -HaveCount 2
    $MultiVfsInfo.DisplayName | Should -Be 'BitRock InstallBuilder Enterprise'
    $MultiVfsInfo.PayloadFiles | Should -Contain 'bin/builder.exe'
  }

  It 'Should catalog and extract all installed payload files from legacy Metakit media' {
    $Destination = Join-Path $Script:FixtureDirectory 'legacy-expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = @(Expand-InstallBuilderInstaller -Path $Script:InstallBuilderLegacyFixture -DestinationPath $Destination -CollisionAction Rename)
      $Extracted | Should -HaveCount 89
      (Get-Content -LiteralPath (Join-Path $Destination 'project.xml') -Raw) | Should -Match '<version>3.6.0</version>'
      (Get-Content -LiteralPath (Join-Path $Destination 'demo\docs\license.txt') -Raw) | Should -BeExactly "Sample license`n"
      (Get-Item -LiteralPath (Join-Path $Destination 'demo\bin\demo.txt')).Length | Should -Be 158
      (Get-Item -LiteralPath (Join-Path $Destination 'bin\builder.exe')).Length | Should -Be 2952180
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject an out-of-range Metakit root before reading its catalog' {
    $CorruptFixture = Join-Path $Script:FixtureDirectory 'installbuilder-corrupt-metakit-root.exe'
    Copy-Item -LiteralPath $Script:InstallBuilderLegacyFixture -Destination $CorruptFixture -Force
    $Info = Get-InstallBuilderInfo -Path $Script:InstallBuilderLegacyFixture
    $Layout = $Info.MetakitLayouts | Select-Object -First 1
    $Stream = [IO.File]::Open($CorruptFixture, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $Stream.Position = [long]$Layout.HeaderOffset + [long]$Layout.Length - 4
      $Stream.Write([byte[]](0xFF, 0xFF, 0xFF, 0xFF))
    } finally {
      $Stream.Dispose()
    }

    { [Dumplings.InstallBuilder.InstallBuilderMetakitArchive]::Open($CorruptFixture, [long]$Layout.HeaderOffset, 200000, 67108864).Dispose() } | Should -Throw '*commit footer is malformed*'
  }

  It 'Should project current structured evidence into schema-valid WinGet suggestions' {
    Import-Module (Join-Path $Script:DumplingsModuleRoot 'Index.ps1') -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:InstallBuilderCurrentFixture
    $Fields = $Analysis.SuggestedManifestFields

    $Fields.InstallerType | Should -Be 'exe'
    $Fields.ProductCode | Should -Be 'InstallBuilder for Windows 26.8.0'
    $Fields.InstallerSwitches.Silent | Should -Be '--mode unattended --unattendedmodeui none'
    $Fields.InstallerSwitches.InstallLocation | Should -Be '--prefix "<INSTALLPATH>"'
    $Fields.AppsAndFeaturesEntries | Should -HaveCount 1
    $Fields.AppsAndFeaturesEntries[0].ProductCode | Should -Be 'InstallBuilder for Windows 26.8.0'

    $FamilyFields = (& (Get-Module WinGetAnalysis) { (Get-WinGetInstallerFamilySuggestion -Family InstallBuilder).ManifestFields })
    $FamilyFields.InstallerType | Should -Be 'exe'
    $FamilyFields.PSObject.Properties.Name | Should -Not -Contain 'InstallModes'
    $FamilyFields.PSObject.Properties.Name | Should -Not -Contain 'InstallerSwitches'
  }
}
