BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\ZeroInstall'
  $Script:DeepLInstaller = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name 'DeepLSetup.exe' -Uri 'https://appdownload.deepl.com/windows/0install/DeepLSetup.exe'
  $Script:CliBootstrapper = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name '0install.exe' -Uri 'https://github.com/0install/0install-win/releases/download/2.29.0/0install.exe' -Sha256 'D55F79AC984EF42877810199CD8A2D4DEAC7F65C8EEC517874091444C24C2753'
  $Script:GuiBootstrapper = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name 'zero-install.exe' -Uri 'https://github.com/0install/0install-win/releases/download/2.29.0/zero-install.exe' -Sha256 '0F66626EB19B59494D99D807934453841CB2F96940775490648F4DAB117B10EA'

  $Script:FeedContent = @'
<?xml version="1.0" encoding="utf-8"?>
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface"
           uri="https://downloads.example.test/product.xml">
  <name>Example Product</name>
  <summary>Example summary</summary>
  <publisher>Example Publisher</publisher>
  <homepage>https://example.test/product</homepage>
  <group arch="Windows-x86_64" stability="stable">
    <implementation id="sha256new_X64" version="2.0.0" released="2026-07-01">
      <archive href="https://downloads.example.test/product-x64.tar.zst" size="1234" type="application/x-zstd-compressed-tar" />
    </implementation>
  </group>
  <group arch="Windows-i486">
    <implementation id="sha256new_X86" version="2.0.0-rc1" released="2026-06-30" rollout-percentage="25" />
  </group>
  <capabilities xmlns="http://0install.de/schema/desktop-integration/capabilities">
    <url-protocol id="example" />
    <file-type id="Example.Document">
      <extension value=".example" />
    </file-type>
  </capabilities>
</interface>
'@
}

Describe 'Zero Install feed conversion' {
  It 'converts identity, inherited implementation metadata, architecture, and associations without fetching' {
    $Feed = ConvertFrom-ZeroInstallFeed -Content $Script:FeedContent

    $Feed.InterfaceUri | Should -Be 'https://downloads.example.test/product.xml'
    $Feed.Name | Should -Be 'Example Product'
    $Feed.Publisher | Should -Be 'Example Publisher'
    $Feed.Architectures | Should -Be @('x64', 'x86')
    $Feed.Protocols | Should -Be @('example')
    $Feed.FileExtensions | Should -Be @('example')
    $Feed.Implementations | Should -HaveCount 2
    $Feed.StableImplementations | Should -HaveCount 1
    $Feed.Implementations[0].Architecture | Should -Be 'x64'
    $Feed.Implementations[0].Stability | Should -Be 'stable'
    $Feed.Implementations[1].Architecture | Should -Be 'x86'
    $Feed.Implementations[1].Stability | Should -Be 'testing'
    $Feed.Implementations[1].RolloutPercentage | Should -Be '25'
  }

  It 'rejects DTD-bearing feed XML' {
    { ConvertFrom-ZeroInstallFeed -Content '<!DOCTYPE interface [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><interface><name>&x;</name></interface>' } | Should -Throw
  }
}

Describe 'Zero Install bootstrapper parser' {
  It 'reads the configured DeepL bootstrapper and derives its exact uninstall identity' {
    $Info = Get-ZeroInstallInfo -Path $Script:DeepLInstaller

    $Info.InstallerType | Should -Be 'Zero Install'
    $Info.BootstrapperVariant | Should -Be 'GUI'
    $Info.AppUri | Should -Be 'https://appdownload.deepl.com/windows/0install/deepl.xml'
    $Info.AppName | Should -Be 'DeepL'
    $Info.ProductCode | Should -Be 'https%3a##appdownload.deepl.com#windows#0install#deepl.xml'
    $Info.Scope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.CustomizableStorePath | Should -BeTrue
    $Info.EstimatedRequiredSpace | Should -Be 225280000
    $Info.InstallModes | Should -Be @('interactive', 'silent', 'silentWithProgress')
    $Info.InstallerSwitches.Silent | Should -Be '--verysilent'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '--silent'
    $Info.InstallerSwitches.InstallLocation | Should -Be '--store-path="<INSTALLPATH>"'
    $Info.ScopeSwitches.Machine | Should -Be '--machine'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.ExtractedFiles | Should -Contain 'BootstrapConfig.ini'
    $Info.ExtractedFiles | Should -Contain 'SplashScreen.png'
  }

  It 'combines caller-supplied feed evidence without selecting a target version' {
    $Info = Get-ZeroInstallInfo -Path $Script:DeepLInstaller -FeedContent $Script:FeedContent

    $Info.DisplayName | Should -Be 'Example Product'
    $Info.Publisher | Should -Be 'Example Publisher'
    $Info.Architectures | Should -Be @('x64', 'x86')
    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example')
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.Warnings | Should -Contain "The supplied feed URI 'https://downloads.example.test/product.xml' does not match embedded app_uri 'https://appdownload.deepl.com/windows/0install/deepl.xml'."
  }

  It 'distinguishes generic console and GUI launchers without inventing app metadata' {
    $Cli = Get-ZeroInstallInfo -Path $Script:CliBootstrapper
    $Gui = Get-ZeroInstallInfo -Path $Script:GuiBootstrapper

    $Cli.BootstrapperVariant | Should -Be 'CLI'
    $Gui.BootstrapperVariant | Should -Be 'GUI'
    $Cli.AppUri | Should -BeNullOrEmpty
    $Gui.AppUri | Should -BeNullOrEmpty
    $Cli.ProductCode | Should -BeNullOrEmpty
    $Gui.ProductCode | Should -BeNullOrEmpty
    $Cli.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Gui.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Cli.InstallModes | Should -Be @('interactive')
    $Gui.InstallModes | Should -Be @('interactive')
  }

  It 'honors an adjacent bootstrap INI before the embedded configuration' {
    $Installer = Join-Path $TestDrive 'SidecarSetup.exe'
    Copy-Item -LiteralPath $Script:DeepLInstaller -Destination $Installer
    @'
[bootstrap]
app_uri = https://downloads.example.test/sidecar.xml
app_name = Sidecar Product
integrate_args = --add-all
'@ | Set-Content -LiteralPath ([IO.Path]::ChangeExtension($Installer, '.ini')) -Encoding utf8NoBOM

    $Info = Get-ZeroInstallInfo -Path $Installer

    $Info.ConfigurationSource | Should -Be 'Adjacent INI: SidecarSetup.ini'
    $Info.AppName | Should -Be 'Sidecar Product'
    $Info.ProductCode | Should -Be 'https%3a##downloads.example.test#sidecar.xml'
    $Info.EmbeddedBootstrapConfig.Sections.bootstrap.app_name | Should -Be 'DeepL'
    $Info.Warnings | Should -Contain 'The adjacent INI overrides the embedded bootstrap configuration at runtime; ensure the package delivers both files together.'
  }

  It 'enumerates managed resources through a caller-owned stream and restores its position' {
    $Stream = [IO.File]::OpenRead($Script:DeepLInstaller)
    $Stream.Position = 19
    try {
      $Layout = Get-PELayout -Stream $Stream
      $Resource = Get-PEManagedResourceInfo -Stream $Stream -Layout $Layout -Name 'ZeroInstall.BootstrapConfig.ini' | Select-Object -First 1

      $Resource.Name | Should -Be 'ZeroInstall.BootstrapConfig.ini'
      $Resource.Size | Should -BeGreaterThan 0
      $Stream.Position | Should -Be 19
      [object]::ReferenceEquals($Resource.SourceStream, $Stream) | Should -BeTrue
    } finally { $Stream.Dispose() }
  }

  It 'exports selected resources without executing the bootstrapper' {
    $Destination = Join-Path $TestDrive 'ZeroInstallExpansion'
    $Files = @(Expand-ZeroInstallInstaller -Path $Script:DeepLInstaller -DestinationPath $Destination -Name 'BootstrapConfig.ini')

    $Files | Should -HaveCount 1
    $Files[0].Name | Should -Be 'BootstrapConfig.ini'
    (Get-Content -LiteralPath $Files[0].FullName -Raw) | Should -Match '(?m)^app_uri\s*=\s*https://appdownload\.deepl\.com/windows/0install/deepl\.xml\r?$'
  }

  It 'rejects a managed PE without Zero Install bootstrap configuration' {
    Test-ZeroInstallInstaller -Path (Get-Process -Id $PID).Path | Should -BeFalse
  }

  It 'rejects a truncated managed resource record deterministically' {
    $Malformed = Join-Path $TestDrive 'MalformedZeroInstall.exe'
    Copy-Item -LiteralPath $Script:DeepLInstaller -Destination $Malformed
    $Resource = Get-PEManagedResourceInfo -Path $Malformed -Name 'ZeroInstall.BootstrapConfig.ini' | Select-Object -First 1
    $Stream = [IO.File]::Open($Malformed, 'Open', 'ReadWrite', 'None')
    try {
      $Stream.Position = $Resource.Offset - 4
      $Length = [BitConverter]::GetBytes([uint32]1000000)
      $Stream.Write($Length, 0, $Length.Length)
    } finally { $Stream.Dispose() }

    { Get-ZeroInstallInfo -Path $Malformed } | Should -Throw '*truncated*'
    Test-ZeroInstallInstaller -Path $Malformed | Should -BeFalse
  }

  It 'routes DeepL through the structured analyzer before generic EXE fallbacks' {
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:DeepLInstaller
    $Candidate = $Analysis.FamilyCandidates | Where-Object Family -EQ 'Zero Install' | Select-Object -First 1
    $Result = $Analysis.ParserResults | Where-Object Name -EQ 'Zero Install' | Select-Object -First 1

    $Candidate.Confidence | Should -Be 'high'
    $Candidate.MatchedMarkers | Should -Contain 'CLR ManifestResource ZeroInstall.BootstrapConfig.ini'
    $Result.Success | Should -BeTrue
    $Result.Result.ProductCode | Should -Be 'https%3a##appdownload.deepl.com#windows#0install#deepl.xml'
    $Result.Result.SuggestedManifestFields.ScopeSwitches.Machine | Should -Be '--machine'
  }
}
