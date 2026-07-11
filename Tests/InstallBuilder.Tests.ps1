BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallBuilder.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallBuilder'

  function New-TestInstallBuilderFixture {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ProjectXml)
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try {
      $Bytes = [Text.Encoding]::UTF8.GetBytes($ProjectXml)
      $Encoder.Write($Bytes, 0, $Bytes.Length)
    } finally { $Encoder.Dispose() }
    $Path = Join-Path $Script:FixtureDirectory $Name
    [IO.File]::WriteAllBytes($Path, [Text.Encoding]::ASCII.GetBytes("MZ`0MetakitVfs`0project.xml`0manifest.txt`0cookfsinfo.txt`0") + $Compressed.ToArray())
    return $Path
  }

  function ConvertTo-TestBigEndianUInt32 {
    param([Parameter(Mandatory)][uint32]$Value)
    $Bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($Bytes)
    return $Bytes
  }

  function New-TestCookfsInstallBuilderFixture {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$ProjectXml,
      [switch]$UnsupportedCookfsCompression
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
        $Index.Write([byte[]]::new(8), 0, 8)
        foreach ($Value in @([uint32]1, [uint32]$Page, [uint32]0, [uint32]$File.Content.Length)) {
          $Bytes = ConvertTo-TestBigEndianUInt32 -Value $Value
          $Index.Write($Bytes, 0, $Bytes.Length)
        }
      }
      $StoredIndex = [byte[]](0) + $Index.ToArray()
    } finally {
      $Index.Dispose()
    }

    $Pages = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($File in $Files) {
      $Pages.Add(([byte[]](0) + $File.Content))
    }
    $Cookfs = [IO.MemoryStream]::new()
    try {
      foreach ($Page in $Pages) { $Cookfs.Write($Page, 0, $Page.Length) }
      $Cookfs.Write([byte[]]::new($Pages.Count * 16), 0, $Pages.Count * 16)
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
        $Prefix = [Text.Encoding]::ASCII.GetBytes("MZ`0") + $Cookfs.ToArray() + [Text.Encoding]::ASCII.GetBytes("MetakitVfs`0project.xml`0")
        [IO.File]::WriteAllBytes($Path, $Prefix + $Compressed.ToArray())
        if ($UnsupportedCookfsCompression) {
          $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
          try {
            $Stream.Position = 3 # First CookFS page follows the MZ prefix.
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
  It 'Should recover a zlib project record and parse product, ARP, and scope evidence' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder.exe' -ProjectXml @'
<project>
  <shortName>Example</shortName>
  <fullName>Example InstallBuilder Product</fullName>
  <version>1.2.3</version>
  <vendor>Example Vendor</vendor>
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

    $Info.InstallerType | Should -Be 'InstallBuilder'
    $Info.ProductCode | Should -Be 'Example 1.2.3'
    $Info.DisplayName | Should -Be 'Example InstallBuilder Product'
    $Info.DisplayVersion | Should -Be '1.2.3'
    $Info.Publisher | Should -Be 'Example Vendor'
    $Info.Scope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.RegistryWrites | Should -HaveCount 1
  }

  It 'Should export project.xml through the bounded extractor when no CookFS payload is present' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-expand.exe' -ProjectXml '<project><shortName>Expand</shortName><version>2.0</version></project>'
    $Destination = Join-Path $Script:FixtureDirectory 'expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination
      $Extracted | Should -HaveCount 1
      $Extracted[0].Name | Should -Be 'project.xml'
      (Get-Content -LiteralPath $Extracted[0].FullName -Raw) | Should -Match '<shortName>Expand</shortName>'
      { Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name '*.exe' } | Should -Throw '*CFS0002*'
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
      $Info.PayloadFiles | Should -Contain 'app.exe'
      $Info.PayloadFiles | Should -Contain 'readme.txt'
      $Info.PayloadFiles | Should -Not -Contain 'app.exe___bitrockBigFile1'
      $Info.CookfsInfo.CompressionTypes | Should -Be @('None')

      $Extracted = Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name 'app.exe'
      $Extracted | Should -HaveCount 1
      $Extracted[0].Name | Should -Be 'app.exe'
      [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Extracted[0].FullName)) | Should -Be 'first-second'
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject unsupported CookFS custom compression before payload extraction' {
    $Fixture = New-TestCookfsInstallBuilderFixture -Name 'synthetic-installbuilder-unsupported-cookfs.exe' -ProjectXml '<project><shortName>Unsupported</shortName><version>1.0</version></project>' -UnsupportedCookfsCompression
    $Destination = Join-Path $Script:FixtureDirectory 'unsupported-cookfs-expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallBuilderInfo -Path $Fixture
      $Info.CookfsInfo.HasUnsupportedCompression | Should -BeTrue
      $Info.Warnings | Should -Contain 'The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password.'
      { Expand-InstallBuilderInstaller -Path $Fixture -DestinationPath $Destination -Name 'app.exe' } | Should -Throw '*unsupported custom or encrypted compression*'
      Test-Path -LiteralPath (Join-Path $Destination 'app.exe') | Should -BeFalse
    } finally {
      Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should surface InstallBuilder metadata in the static installer analyzer' {
    $Fixture = New-TestInstallBuilderFixture -Name 'synthetic-installbuilder-analyzer.exe' -ProjectXml '<project><shortName>Analyzer</shortName><fullName>Analyzer Product</fullName><version>3.0</version><vendor>Example Vendor</vendor><requireInstallationByRootUser>1</requireInstallationByRootUser></project>'
    Import-Module (Join-Path $PSScriptRoot '..' 'Index.ps1') -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $Fixture
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'InstallBuilder' } | Select-Object -First 1

    $Result.Success | Should -BeTrue
    $Result.Result.ProductName | Should -Be 'Analyzer Product'
    $Result.Result.ProductCode | Should -Be 'Analyzer 3.0'
    $Result.Result.Scope | Should -Be 'machine'
  }
}
