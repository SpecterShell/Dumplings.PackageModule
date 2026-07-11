BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallerBridge.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'MSI.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'NSIS.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Inno.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'AdvancedInstaller.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'QtInstallerFramework.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'SetupFactory.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallerBridge'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [switch]$UseSourceForgeMetaRefresh
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url -UseSourceForgeMetaRefresh:$UseSourceForgeMetaRefresh
  }

  function Add-TestInt64LE {
    param([System.Collections.Generic.List[byte]]$Bytes, [int64]$Value)

    $Bytes.AddRange([System.BitConverter]::GetBytes($Value))
  }

  function New-TestQtInstallerFrameworkFixture {
    param(
      [string]$Name,
      [string]$InstallerXml
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $Bytes = [System.Collections.Generic.List[byte]]::new()
    $Bytes.AddRange([byte[]](0x4d, 0x5a))
    $Bytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("accept-licenses`0default-answer`0confirm-command`0check-updates`0create-offline`0clear-cache`0"))
    while ($Bytes.Count -lt 512) { $Bytes.Add(0) }

    $EndOfExecutable = $Bytes.Count
    $MetaStart = $Bytes.Count
    $MetaBytes = [System.Text.Encoding]::UTF8.GetBytes($InstallerXml)
    $Bytes.AddRange($MetaBytes)

    $OperationsStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value 0
    Add-TestInt64LE -Bytes $Bytes -Value 0
    $OperationsLength = $Bytes.Count - $OperationsStart

    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value 0
    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexLength = $Bytes.Count - $CollectionIndexStart

    Add-TestInt64LE -Bytes $Bytes -Value ($CollectionIndexStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $CollectionIndexLength
    Add-TestInt64LE -Bytes $Bytes -Value ($MetaStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $MetaBytes.Length
    Add-TestInt64LE -Bytes $Bytes -Value ($OperationsStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $OperationsLength
    Add-TestInt64LE -Bytes $Bytes -Value 1

    $BinaryContentSize = ($Bytes.Count + 24) - $EndOfExecutable
    Add-TestInt64LE -Bytes $Bytes -Value $BinaryContentSize
    Add-TestInt64LE -Bytes $Bytes -Value 0x12023233
    $Bytes.AddRange([byte[]](0xf8, 0x68, 0xd6, 0x99, 0x1c, 0x0a, 0x63, 0xc2))

    [System.IO.File]::WriteAllBytes($FixturePath, $Bytes.ToArray())
    return $FixturePath
  }
}

Describe 'Installer bridge' {
  It 'Should parse Setup Factory metadata through the MIT wrapper' {
    $Fixture = Get-InstallerFixture -Name 'OutCALL-2.0.exe' -Url 'https://github.com/bicomsystems/outcall2/releases/download/v2.0/OutCALL-2.0.exe'
    $Info = Get-SetupFactoryInfo -Path $Fixture
    $Info.DisplayName | Should -Be 'OutCALL'
    $Info.DisplayVersion | Should -Be '2.0'
    $Info.ProductCode | Should -Be 'OutCALL2.0'
    $Info.Scope | Should -Be 'machine'
  }

  It 'Should convert electron-builder latest.yml content without fetching it' {
    $LatestYaml = @'
version: 1.2.3
files:
  - url: App-Setup-1.2.3.exe
    sha512: abcdef
    size: 123456
    blockMapSize: 2345
path: App-Setup-1.2.3.exe
sha512: abcdef
releaseDate: '2026-07-07T00:00:00.000Z'
stagingPercentage: 25
'@
    $Feed = $LatestYaml | ConvertFrom-ElectronBuilderUpdateFeed

    $Feed.Version | Should -Be '1.2.3'
    $Feed.Path | Should -Be 'App-Setup-1.2.3.exe'
    $Feed.Sha512 | Should -Be 'abcdef'
    $Feed.ReleaseDate | Should -Be '2026-07-07T00:00:00.000Z'
    $Feed.StagingPercentage | Should -Be 25
    $Feed.Files | Should -HaveCount 1
    $Feed.Files[0].Url | Should -Be 'App-Setup-1.2.3.exe'
    $Feed.Files[0].Sha512 | Should -Be 'abcdef'
    $Feed.Files[0].Size | Should -Be 123456
    $Feed.Files[0].BlockMapSize | Should -Be 2345
  }

  It 'Should call the InstallerParsers NSIS parser through the MIT wrapper' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'alist-desktop'
    $Info.DisplayVersion | Should -Be '3.60.0'
  }

  It 'Should return FileInfo objects from the InstallerParsers Inno extraction bridge' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'myob-bridge-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'BK5WIN.EXE'

      $Extracted | Should -HaveCount 1
      $Extracted[0] | Should -BeOfType ([System.IO.FileInfo])
      $Extracted[0].VersionInfo.FileVersion | Should -Be '5.55.3.7499'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should read MSI metadata through the InstallerParsers Advanced Installer bridge' {
    $Fixture = Get-InstallerFixture -Name 'TINspireComputerLink-3.9.0.455.exe' -Url 'https://education.ti.com/download/en/ed-tech/82035809F7E6474099944056CCB01C20/AC3AAE51297B4902B6B6CA005B8391F0/TINspireComputerLink-3.9.0.455.exe'
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Path $Fixture -Name 'ComputerLink.msi'

    $MsiInfo.ProductVersion | Should -Be '3.9.0.455'
    $MsiInfo.ProductCode | Should -Be '{6C5AC088-3136-4043-8985-8B0772A9580E}'
  }

  It 'Should call the InstallerParsers Qt Installer Framework parser through the MIT wrapper' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-bridge.exe' -InstallerXml @'
<Installer>
  <Name>Bridge.QtIFW</Name>
  <Version>2.0.0</Version>
  <Publisher>Bridge Publisher</Publisher>
</Installer>
'@
    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Qt Installer Framework'
    $Info.PackageName | Should -Be 'Bridge.QtIFW'
    $Info.DisplayVersion | Should -Be '2.0.0'
    $Info.Publisher | Should -Be 'Bridge Publisher'
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.RequiresExplicitInstallLocation | Should -BeTrue
    $Info.SupportsExistingInstallationOverride | Should -BeFalse
    $Info.RecommendedUpgradeBehavior | Should -Be 'uninstallPrevious'
    $Info.Scope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    Read-ScopeFromQtInstallerFramework -Path $Fixture | Should -Be 'user'
    Read-SupportedScopesFromQtInstallerFramework -Path $Fixture | Should -Be @('user', 'machine')
    Test-QtInstallerFrameworkDualScope -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkCLI -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkSilentInstallation -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkRequiresInstallLocation -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkSupportsExistingInstallationOverride -Path $Fixture | Should -BeFalse
    Read-UpgradeBehaviorFromQtInstallerFramework -Path $Fixture | Should -Be 'uninstallPrevious'
  }

  It 'Should expand Qt Installer Framework resources through the MIT wrapper' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-expand-bridge.exe' -InstallerXml @'
<Installer>
  <Name>Bridge.QtIFW.Expand</Name>
  <Version>2.1.0</Version>
  <Publisher>Bridge Publisher</Publisher>
</Installer>
'@
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-ifw-bridge-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-QtInstallerFramework -Path $Fixture -DestinationPath $ExpandedPath -Name '*.rcc'
      $ResourcePath = Join-Path $Result 'metadata\QResources\0.rcc'

      $ResourcePath | Should -Exist
      (Get-Content -LiteralPath $ResourcePath -Raw) | Should -BeLike '*Bridge.QtIFW.Expand*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should detect a user-only electron-builder NSIS installer through the MIT wrapper' {
    $Fixture = Get-InstallerFixture -Name 'Aircall-Workspace-1.15.13-x64.exe' -Url 'https://download-electron.aircall.io/aircall-workspace/Aircall-Workspace-1.15.13-x64.exe'
    $IsElectronBuilder = Test-ElectronBuilder -Path $Fixture
    $Info = Get-ElectronBuilderNSISInfo -Path $Fixture

    $IsElectronBuilder | Should -BeTrue
    $Info.IsElectronBuilder | Should -BeTrue
    $Info.Architectures | Should -Be @('x64')
    $Info.Architecture | Should -Be 'x64'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.ProductCode | Should -Be '3ec9d337-6374-5d93-9484-d59100254d53'
    $Info.DisplayVersion | Should -Be '1.15.13'
    $Info.Evidence.AppPackageFiles | Should -Contain 'app-64.7z'
  }

  It 'Should detect a universal dual-scope electron-builder NSIS installer through the MIT wrapper' {
    $Fixture = Get-InstallerFixture -Name 'Obsidian-1.12.7.exe' -Url 'https://github.com/obsidianmd/obsidian-releases/releases/download/v1.12.7/Obsidian-1.12.7.exe'
    $IsElectronBuilder = Test-ElectronBuilder -Path $Fixture
    $Info = Get-ElectronBuilderNSISInfo -Path $Fixture

    $IsElectronBuilder | Should -BeTrue
    $Info.IsElectronBuilder | Should -BeTrue
    $Info.Architectures | Should -Be @('arm64', 'x64', 'x86')
    $Info.Architecture | Should -Be 'x86'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.ProductCode | Should -Be 'bd400747-f0c1-5638-a859-982036102edf'
    $Info.DisplayVersion | Should -Be '1.12.7'
    $Info.Evidence.AppPackageFiles | Should -Contain 'app-arm64.7z'
    $Info.Evidence.AppPackageFiles | Should -Contain 'app-64.7z'
    $Info.Evidence.AppPackageFiles | Should -Contain 'app-32.7z'
  }

  It 'Should classify the documented electron-builder example <PackageIdentifier>' -ForEach @(
    @{
      PackageIdentifier = 'GameSir.GameSirT4kApp'
      Name              = 'GameSir-T4k-App-Setup-0.3.3.exe'
      Url               = 'https://xjdl.bigeyes.com/download/GameSir-T4k-App-Setup-0.3.3.exe'
      Architecture      = 'x86'
      SupportedScopes   = @('user')
      SupportsDualScope = $false
      ProductCode       = '444d7d04-f102-57c2-a67b-de6a06736d98'
      DisplayVersion    = '0.3.3'
      AppPackageFile    = 'app-32.7z'
    }
    @{
      PackageIdentifier = 'GameSir.GameSirConnect'
      Name              = 'GameSir-Connect-Setup-1.6.8.exe'
      Url               = 'https://xjdl.bigeyes.com/download/GameSir-Connect-Setup-1.6.8.exe'
      Architecture      = 'x86'
      SupportedScopes   = @('user', 'machine')
      SupportsDualScope = $true
      ProductCode       = '1796fd17-f3e3-54e3-87c2-6726acaeef5f'
      DisplayVersion    = '1.6.8'
      AppPackageFile    = 'app-32.7z'
    }
    @{
      PackageIdentifier = 'GDevelop.GDevelop'
      Name              = 'GDevelop-5-Setup-5.6.273.exe'
      Url               = 'https://github.com/4ian/GDevelop/releases/download/v5.6.273/GDevelop-5-Setup-5.6.273.exe'
      Architecture      = 'x64'
      SupportedScopes   = @('user', 'machine')
      SupportsDualScope = $true
      ProductCode       = 'c2a9b91e-8206-5b4e-b81d-9aa27463c28e'
      DisplayVersion    = '5.6.273'
      AppPackageFile    = 'app-64.7z'
    }
    @{
      PackageIdentifier = 'GauzyTech.NeatReader'
      Name              = 'NeatReader Setup 9.0.10.exe'
      Url               = 'https://neat-reader-release.oss-cn-hongkong.aliyuncs.com/NeatReader%20Setup%209.0.10.exe'
      Architecture      = 'x86'
      SupportedScopes   = @('machine')
      SupportsDualScope = $false
      ProductCode       = 'bbff271c-caf8-5302-b3c6-6d9ee38f27e3'
      DisplayVersion    = '9.0.10'
      AppPackageFile    = 'app-32.7z'
    }
    @{
      PackageIdentifier = 'JGraph.Draw'
      Name              = 'draw.io-30.2.6-windows-installer.exe'
      Url               = 'https://github.com/jgraph/drawio-desktop/releases/download/v30.2.6/draw.io-30.2.6-windows-installer.exe'
      Architecture      = 'x64'
      SupportedScopes   = @('machine')
      SupportsDualScope = $false
      ProductCode       = '27a75bf3-be48-5c35-934f-8491cf108abe'
      DisplayVersion    = '30.2.6'
      AppPackageFile    = 'app-64.7z'
    }
  ) {
    $Fixture = Get-InstallerFixture -Name $Name -Url $Url
    $IsElectronBuilder = Test-ElectronBuilder -Path $Fixture
    $Info = Get-ElectronBuilderNSISInfo -Path $Fixture

    $IsElectronBuilder | Should -BeTrue
    $Info.IsElectronBuilder | Should -BeTrue
    $Info.Architecture | Should -Be $Architecture
    $Info.Architectures | Should -Be @($Architecture)
    $Info.SupportedScopes | Should -Be $SupportedScopes
    $Info.SupportsDualScope | Should -Be $SupportsDualScope
    $Info.ProductCode | Should -Be $ProductCode
    $Info.DisplayVersion | Should -Be $DisplayVersion
    $Info.Evidence.AppPackageFiles | Should -Contain $AppPackageFile
  }
}

Describe 'Bridge regressions' {
  It 'Should keep parser modules outside the shared Dumplings session autoload path' {
    Test-Path (Join-Path $PSScriptRoot '..' '..' '..' 'Modules' 'InstallerParsers' 'Index.ps1') | Should -BeFalse
    Test-Path (Join-Path $PSScriptRoot '..' '..' '..' 'Modules' 'InstallerParsers' 'GPL3') | Should -BeFalse
    Test-Path (Join-Path $PSScriptRoot '..' '..' '..' 'Modules' 'InstallerParsers' 'GPL2') | Should -BeFalse
  }

  It 'Should keep task scripts on MIT helper names instead of direct CLI calls' {
    $TaskRoot = Join-Path $PSScriptRoot '..' '..' '..' 'Tasks'
    $TaskPieces = @(Get-ChildItem -Path $TaskRoot -Filter '*.ps1' -Recurse -File)
    $NsisTasks = @($TaskPieces | Where-Object { (Get-Content $_.FullName -Raw) -match '\bGet-NSISInfo\b' } | Select-Object -ExpandProperty DirectoryName -Unique)
    $InnoTasks = @($TaskPieces | Where-Object { (Get-Content $_.FullName -Raw) -match '\bGet-InnoInfo\b|\bExpand-InnoInstaller\b' } | Select-Object -ExpandProperty DirectoryName -Unique)
    $AdvancedInstallerTasks = @($TaskPieces | Where-Object { (Get-Content $_.FullName -Raw) -match '\bExpand-AdvancedInstaller\b' } | Select-Object -ExpandProperty DirectoryName -Unique)
    $DirectCliTasks = @($TaskPieces | Where-Object { (Get-Content $_.FullName -Raw) -match 'InstallerParsers\\GPL|InstallerParsers\.GPL|Cli\.ps1' })

    $NsisTasks.Count | Should -Be 71
    $InnoTasks.Count | Should -Be 3
    $AdvancedInstallerTasks.Count | Should -Be 35
    $DirectCliTasks.Count | Should -Be 0
  }

  It 'Should keep MIT wrappers from importing the GPL modules into the shared session' {
    $NsisContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'NSIS.psm1') -Raw
    $InnoContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'Inno.psm1') -Raw
    $AdvancedInstallerContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'AdvancedInstaller.psm1') -Raw
    $BridgeContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallerBridge.psm1') -Raw

    $NsisContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $InnoContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $AdvancedInstallerContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $BridgeContent | Should -Match 'pwsh'
    $BridgeContent | Should -Match 'Cli\.ps1'
  }
}
