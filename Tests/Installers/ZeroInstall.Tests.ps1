. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  . (Join-Path $Script:DumplingsModuleRoot 'Index.ps1')

  $Script:FixtureDirectory = $TestDrive
  $Script:DeepLInstaller = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'DeepLSetup.exe') -Uri 'https://appdownload.deepl.com/windows/0install/DeepLSetup.exe'
  $Script:CliBootstrapper = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name '0install.exe') -Uri 'https://github.com/0install/0install-win/releases/download/2.29.0/0install.exe' -Sha256 'D55F79AC984EF42877810199CD8A2D4DEAC7F65C8EEC517874091444C24C2753'
  $Script:GuiBootstrapper = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'zero-install.exe') -Uri 'https://github.com/0install/0install-win/releases/download/2.29.0/zero-install.exe' -Sha256 '0F66626EB19B59494D99D807934453841CB2F96940775490648F4DAB117B10EA'
  $Script:SourceBuiltLegacyBootstrapper = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\ZeroInstall\2.11.5\0bootstrap.exe'
  $Script:HistoricalBootstrappers = [ordered]@{}
  foreach ($Fixture in @(
      @{ Version = '2.16.0'; Sha256 = '2A85F26B8EC9DFC9D48057609B817F83DFE87B7BDD7F5AA1B85CCD5D07843A07' }
      @{ Version = '2.21.0'; Sha256 = '9333703B3E37ABA3361DCEDB0E342D00724E24C66F14EE05D1ED8B51BBFF11A1' }
      @{ Version = '2.22.0'; Sha256 = '58586E54D6E2460B5F0FF3A521A8C71FD0132DA77CAF86300B87702EDF37C331' }
      @{ Version = '2.23.0'; Sha256 = 'A34A95AB7E5EC6D36CC7E6637FB56C7CED1B421BC81843F3B1140BC7DDEC711D' }
      @{ Version = '2.23.1'; Sha256 = '39EDF7035668EDD9A84076DD02ACAF5EBF9993DAE9FBC8E621B1DD8F491D7CFF' }
      @{ Version = '2.23.3'; Sha256 = '0EA0188D22DCF5AA611A61AB525FE0228325C241E631D15DBC2908A869858E9D' }
      @{ Version = '2.24.0'; Sha256 = '29FA1A7214F3B5C5E6F05407BF4DE0D045D68E41B112D8E93B1C163A58C0890F' }
      @{ Version = '2.24.6'; Sha256 = '2D903593751095930B960D25A798D0BB3916DD75ECDA29724822E61A6944827A' }
      @{ Version = '2.24.8'; Sha256 = '733635A9A6A386A9AA08247E7B613C8581F5660C21C1CC46AEFCB906F9C45BB5' }
      @{ Version = '2.25.12'; Sha256 = 'E918AA819960F61FCF1D5BAC0ED211CA8F2809ED823DE7047D0B27CC7F85F590' }
    )) {
    $Script:HistoricalBootstrappers[$Fixture.Version] = Get-DumplingsTestFixture -RelativePath "Installers\ZeroInstall\ZeroInstall.ZeroInstall\$($Fixture.Version)\zero-install.exe" -Uri "https://github.com/0install/0install-win/releases/download/$($Fixture.Version)/zero-install.exe" -Sha256 $Fixture.Sha256
  }

  function New-ZeroInstallFixedLineBootstrapper {
    param (
      [Parameter(Mandatory)][string]$Version,
      [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Values
    )

    $Source = $Script:HistoricalBootstrappers[$Version]
    $Target = Join-Path $TestDrive "zero-install-$Version-custom.exe"
    Remove-Item -LiteralPath $Target, "$Target.config", ([IO.Path]::ChangeExtension($Target, '.ini')) -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $Source -Destination $Target -Force
    $Resource = Get-PEManagedResourceInfo -Path $Target -Name 'ZeroInstall.EmbeddedConfig.txt' | Select-Object -First 1
    $Stream = [IO.File]::Open($Target, 'Open', 'ReadWrite', 'None')
    try {
      $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Resource.Offset -Count ([int]$Resource.Size)
      $Text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
      $LineEnding = $Text.Contains("`r`n", [StringComparison]::Ordinal) ? "`r`n" : "`n"
      $Lines = [Collections.Generic.List[string]]::new([string[]]($Text -split '\r?\n'))
      if ($Lines.Count -gt 0 -and $Lines[$Lines.Count - 1].Length -eq 0) { $Lines.RemoveAt($Lines.Count - 1) }
      $Values.Count | Should -Be $Lines.Count
      for ($Index = 0; $Index -lt $Values.Count; $Index++) {
        $Replacement = [string]$Values[$Index]
        if ([Text.Encoding]::UTF8.GetByteCount($Replacement) -gt [Text.Encoding]::UTF8.GetByteCount($Lines[$Index])) { throw "Replacement $Index does not fit the fixed-width Zero Install field." }
        $Lines[$Index] = $Replacement.PadRight($Lines[$Index].Length)
      }
      $PatchedBytes = [Text.Encoding]::UTF8.GetBytes(($Lines -join $LineEnding) + $LineEnding)
      $PatchedBytes.Length | Should -Be $Resource.Size
      $Stream.Position = $Resource.Offset
      $Stream.Write($PatchedBytes)
    } finally { $Stream.Dispose() }
    return $Target
  }

  function New-ZeroInstallIniBootstrapper {
    param (
      [Parameter(Mandatory)][string]$Version,
      [Parameter(Mandatory)][string]$Content
    )

    $Target = Join-Path $TestDrive "zero-install-$Version-custom.exe"
    Remove-Item -LiteralPath $Target, "$Target.config", ([IO.Path]::ChangeExtension($Target, '.ini')) -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $Script:HistoricalBootstrappers[$Version] -Destination $Target -Force
    Set-Content -LiteralPath ([IO.Path]::ChangeExtension($Target, '.ini')) -Value $Content -Encoding utf8NoBOM
    return $Target
  }

  function New-ZeroInstallLegacyIdentityBootstrapper {
    $Target = Join-Path $TestDrive 'zero-install-2.11.5-legacy.exe'
    if (-not (Test-Path -LiteralPath $Target)) {
      $Source = @'
using System.Reflection;
[assembly: AssemblyVersion("2.11.5.0")]
[assembly: AssemblyFileVersion("2.11.5.0")]
namespace ZeroInstall.Bootstrap {
  public sealed class BootstrapProcess { }
}
'@
      Add-Type -TypeDefinition $Source -OutputAssembly $Target
    }
    return $Target
  }

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
  <group arch="Windows-i486" if-0install-version="2.30..">
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

  $Script:AdvancedFeedContent = @'
<?xml version="1.0" encoding="utf-8"?>
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://downloads.example.test/product.xml">
  <name>Example Product</name>
  <publisher>Example Publisher</publisher>
  <group arch="Windows-*">
    <package-implementation package="example-product" version="3.0.0" stability="stable">
      <requires interface="https://example.test/runtime.xml" importance="essential">
        <version not-before="8.0" before="9.0" />
      </requires>
      <recipe>
        <archive href="payload/product.zip" size="2048" type="application/zip" extract="app" start-offset="16" />
      </recipe>
    </package-implementation>
  </group>
</interface>
'@

  $Script:StructuredFeedContent = @'
<?xml version="1.0" encoding="utf-8"?>
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" xmlns:cap="http://0install.de/schema/desktop-integration/capabilities" uri="https://downloads.example.test/structured.xml" min-injector-version="2.20" xml:base="https://cdn.example.test/root/">
  <name>Structured Product</name>
  <publisher>Structured Publisher</publisher>
  <feed src="more.xml" arch="Windows-x86_64" />
  <group arch="Windows-x86_64" license="MIT" main="app.exe">
    <requires interface="runtime.xml" command="run" importance="recommended" use="testing" distribution="0install" os="Windows" version="1..!2" />
    <command name="run" path="app.exe" />
    <group stability="testing" xml:base="payloads/">
      <requires interface="group-helper.xml" />
      <implementation id="sha256new_STRUCTURED" version="4.0" version-modifier="-rc1" released="2026-08-01" rollout-percentage="25" doc-dir="docs">
        <requires interface="leaf-helper.xml" />
        <restricts interface="runtime.xml" version="1..!3" />
        <command name="test" path="test.exe"><requires interface="command-helper.xml" /></command>
        <recipe if-0install-version="2.20..">
          <archive href="product.zip" size="100" type="application/zip" extract="root" dest="app" start-offset="2" />
          <file href="sidecar.dat" size="4" dest="app/sidecar.dat" executable="true" />
          <rename source="app/old.exe" dest="app/new.exe" />
          <remove path="app/obsolete.txt" />
          <copy-from id="sha256new_BASE" source="shared" dest="app/shared" />
          <future-step value="preserve-me" />
        </recipe>
      </implementation>
    </group>
  </group>
  <cap:capabilities os="Linux"><cap:url-protocol id="linux-only" /></cap:capabilities>
  <cap:capabilities os="Windows">
    <cap:url-protocol id="structured" />
    <cap:url-protocol id="Structured.Browser"><cap:known-prefix value="https" /></cap:url-protocol>
    <cap:file-type id="Structured.Document"><cap:extension value=".structured" mime-type="application/x-structured" perceived-type="document" /></cap:file-type>
  </cap:capabilities>
</interface>
'@

  $Script:RichFeedContent = @'
<?xml version="1.0" encoding="utf-8"?>
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" xmlns:cap="http://0install.de/schema/desktop-integration/capabilities" uri="https://downloads.example.test/rich.xml">
  <name>Rich Product</name>
  <name xml:lang="de-DE">Reiches Produkt</name>
  <summary>Rich summary</summary>
  <description xml:lang="en-US">Long description</description>
  <entry-point command="run" binary-name="rich" app-id="Rich.App">
    <name>Rich launcher</name>
    <summary xml:lang="de-DE">Deutsche Zusammenfassung</summary>
    <needs-terminal>false</needs-terminal>
    <suggest-auto-start>true</suggest-auto-start>
    <suggest-send-to>false</suggest-send-to>
  </entry-point>
  <group arch="Windows-x86_64">
    <environment name="GROUP_PATH" insert="group" mode="prepend" />
    <implementation id="sha256new_RICH" version="5.0">
      <manifest-digest sha1="OLD" sha256new="RICH" />
      <binding path="bin/rich.exe" command="run" />
      <command name="run" path="bin/rich.exe">
        <arg>--fixed</arg>
        <for-each item-from="items" separator=","><arg>{item}</arg></for-each>
        <working-dir src="work" />
        <runner interface="runner.xml" command="run"><arg>--runner</arg></runner>
      </command>
    </implementation>
  </group>
  <cap:capabilities os="Windows">
    <cap:url-protocol id="default-protocol"><cap:description>Default protocol</cap:description></cap:url-protocol>
    <cap:url-protocol id="explicit-protocol" explicit-only="true" />
    <cap:file-type id="Default.Document"><cap:extension value=".default" /></cap:file-type>
    <cap:file-type id="Explicit.Document" explicit-only="true"><cap:extension value=".explicit" /></cap:file-type>
  </cap:capabilities>
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
    $Feed.Implementations[1].AppliesToRuntime | Should -BeNullOrEmpty
    $Feed.Implementations[1].Stability | Should -Be 'testing'
    $Feed.Implementations[1].RolloutPercentage | Should -Be '25'
  }

  It 'rejects DTD-bearing feed XML' {
    { ConvertFrom-ZeroInstallFeed -Content '<!DOCTYPE interface [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><interface><name>&x;</name></interface>' } | Should -Throw
  }

  It 'preserves package implementations, relative archives, requirements, and neutral architecture' {
    $Feed = ConvertFrom-ZeroInstallFeed -Content $Script:AdvancedFeedContent -BaseUri 'https://downloads.example.test/product.xml'

    $Feed.Architectures | Should -Be @('neutral')
    $Feed.Implementations | Should -HaveCount 1
    $Feed.Implementations[0].Kind | Should -Be 'package-implementation'
    $Feed.Implementations[0].ArchiveUrl | Should -Be 'https://downloads.example.test/payload/product.zip'
    $Feed.Implementations[0].Archives[0].Extract | Should -Be 'app'
    $Feed.Implementations[0].Archives[0].StartOffset | Should -Be '16'
    $Feed.Requirements[0].Interface | Should -Be 'https://example.test/runtime.xml'
    $Feed.Requirements[0].VersionRanges[0].NotBefore | Should -Be '8.0'
    $Feed.Requirements[0].VersionRanges[0].Before | Should -Be '9.0'
  }

  It 'preserves source-backed inheritance, xml:base, recipes, restrictions, commands, and Windows capabilities' {
    $Feed = ConvertFrom-ZeroInstallFeed -Content $Script:StructuredFeedContent -BaseUri 'https://origin.example.test/feed.xml'
    $Implementation = $Feed.Implementations[0]

    $Feed.MinimumInjectorVersion | Should -Be '2.20'
    $Feed.FeedReferences[0].ResolvedSource | Should -Be 'https://cdn.example.test/root/more.xml'
    $Implementation.Version | Should -Be '4.0-rc1'
    $Implementation.License | Should -Be 'MIT'
    $Implementation.Main | Should -Be 'app.exe'
    $Implementation.DocumentationPath | Should -Be 'docs'
    $Implementation.Requirements.Interface | Should -Be @('leaf-helper.xml', 'group-helper.xml', 'runtime.xml')
    $Implementation.Requirements.ResolvedInterface | Should -Be @('https://cdn.example.test/root/payloads/leaf-helper.xml', 'https://cdn.example.test/root/payloads/group-helper.xml', 'https://cdn.example.test/root/runtime.xml')
    $Implementation.Restrictions[0].VersionRanges[0].Expression | Should -Be '1..!3'
    $Implementation.Commands.Name | Should -Be @('test', 'run')
    $Implementation.Commands[0].Dependencies[0].ResolvedInterface | Should -Be 'https://cdn.example.test/root/payloads/command-helper.xml'
    $Implementation.RetrievalMethods[0].Kind | Should -Be 'recipe'
    $Implementation.RetrievalMethods[0].Steps.Kind | Should -Be @('archive', 'file', 'rename', 'remove', 'copy-from')
    $Implementation.RetrievalMethods[0].ContainsUnknownSteps | Should -BeTrue
    $Implementation.RetrievalMethods[0].UnknownSteps.Name | Should -Be 'future-step'
    $Implementation.Archives[0].ResolvedHref | Should -Be 'https://cdn.example.test/root/payloads/product.zip'
    $Implementation.Archives[0].DownloadSize | Should -Be 102
    $Implementation.Archives[0].Destination | Should -Be 'app'
    $Implementation.Files[0].ResolvedHref | Should -Be 'https://cdn.example.test/root/payloads/sidecar.dat'
    $Implementation.Files[0].Executable | Should -BeTrue
    $Feed.Protocols | Should -Be @('https', 'structured')
    $Feed.FileExtensions | Should -Be @('structured')
    ($Feed.Capabilities | Where-Object OperatingSystem -EQ Linux).WindowsCompatible | Should -BeFalse
    ($Feed.Capabilities | Where-Object Id -EQ 'Structured.Browser').KnownPrefixes | Should -Be 'https'
    $Feed.Diagnostics.Id | Should -Contain 'ZeroInstall.Feed.RecipeStepsUnsupported'
  }

  It 'resolves if-0install-version conditions without discarding raw feed evidence' {
    $Content = @'
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface">
  <name>Conditional Product</name>
  <entry-point command="run" if-0install-version="..!2.29" />
  <feed src="legacy.xml" if-0install-version="..!2.29" />
  <feed-for interface="https://example.test/replacement.xml" if-0install-version="2.29" />
  <group if-0install-version="2.20..!3">
    <implementation id="sha256new_ACTIVE" version="1">
      <requires interface="legacy-runtime.xml" if-0install-version="!2.29" />
      <command name="run" path="app.exe">
        <arg if-0install-version="..!2.29">--legacy</arg>
        <arg if-0install-version="2.29..">--current</arg>
      </command>
      <archive href="legacy.zip" size="10" if-0install-version="..!2.29" />
      <archive href="current.zip" size="20" if-0install-version="2.29.." />
      <recipe if-0install-version="2.20..">
        <remove path="legacy.dat" if-0install-version="..!2.29" />
        <remove path="current.dat" if-0install-version="2.29.." />
      </recipe>
      <recipe if-0install-version="..!2.29"><future-step /></recipe>
    </implementation>
  </group>
  <implementation id="sha256new_EXCLUDED" version="1" if-0install-version="!2.29" />
  <implementation id="sha256new_EXACT" version="1" if-0install-version="2.29" />
  <implementation id="sha256new_UNION" version="1" if-0install-version="..!2.20 | 2.29.." />
</interface>
'@

    $Feed = ConvertFrom-ZeroInstallFeed -Content $Content -RuntimeVersion ([version]'2.29.0')

    $Feed.Implementations.Id | Should -Be @('sha256new_ACTIVE', 'sha256new_EXCLUDED', 'sha256new_EXACT', 'sha256new_UNION')
    $Feed.ApplicableImplementations.Id | Should -Be @('sha256new_ACTIVE', 'sha256new_EXACT', 'sha256new_UNION')
    $Feed.EntryPoints[0].AppliesToRuntime | Should -BeFalse
    $Feed.ApplicableEntryPoints | Should -HaveCount 0
    $Feed.FeedReferences[0].AppliesToRuntime | Should -BeFalse
    $Feed.ApplicableFeedReferences | Should -HaveCount 0
    $Feed.ApplicableFeedFor | Should -Be 'https://example.test/replacement.xml'

    $Implementation = $Feed.Implementations[0]
    $Implementation.Requirements[0].AppliesToRuntime | Should -BeFalse
    $Implementation.ApplicableRequirements | Should -HaveCount 0
    $Implementation.Commands[0].Arguments.AppliesToRuntime | Should -Be @($false, $true)
    $Implementation.Commands[0].ApplicableArguments.Value | Should -Be '--current'
    $Implementation.ArchiveUrl | Should -Be 'current.zip'
    $Implementation.ApplicableArchives.Href | Should -Be 'current.zip'
    $Implementation.RetrievalMethods[2].Steps.AppliesToRuntime | Should -Be @($false, $true)
    $Implementation.RetrievalMethods[2].ApplicableSteps.Path | Should -Be 'current.dat'
    $Feed.Diagnostics.Id | Should -Not -Contain 'ZeroInstall.Feed.RecipeStepsUnsupported'

    $Unresolved = ConvertFrom-ZeroInstallFeed -Content $Content
    $Unresolved.Implementations[1].AppliesToRuntime | Should -BeNullOrEmpty
    $Unresolved.ApplicableImplementations | Should -HaveCount 4
    $Unresolved.Diagnostics.Id | Should -Contain 'ZeroInstall.Feed.RecipeStepsUnsupported'
  }

  It 'rejects malformed if-0install-version ranges' {
    $BadUpperBound = '<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface"><name>Bad range</name><implementation id="sha256new_X" version="1" if-0install-version="2..3" /></interface>'
    $BadUnion = '<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface"><name>Bad range</name><implementation id="sha256new_X" version="1" if-0install-version="2..!!3|" /></interface>'

    { ConvertFrom-ZeroInstallFeed -Content $BadUpperBound -RuntimeVersion ([version]'2.29') } | Should -Throw '*must be exclusive*'
    { ConvertFrom-ZeroInstallFeed -Content $BadUnion -RuntimeVersion ([version]'2.29') } | Should -Throw '*empty union part*'
  }

  It 'preserves localized metadata, entry points, bindings, command arguments, runners, and manifest digests' {
    $Feed = ConvertFrom-ZeroInstallFeed -Content $Script:RichFeedContent -BaseUri 'https://downloads.example.test/rich.xml'
    $Implementation = $Feed.Implementations[0]
    $Command = $Implementation.Commands[0]

    $Feed.Names.Language | Should -Contain 'de-DE'
    $Feed.Descriptions[0].Value | Should -Be 'Long description'
    $Feed.EntryPoints[0].Command | Should -Be 'run'
    $Feed.EntryPoints[0].NeedsTerminal | Should -BeFalse
    $Feed.EntryPoints[0].SuggestAutoStart | Should -BeTrue
    $Implementation.ManifestDigest.Best | Should -Be 'sha256new_RICH'
    $Implementation.ManifestDigest.Available | Should -Be @('sha256new_RICH', 'sha1=OLD')
    $Implementation.Bindings.Kind | Should -Be @('binding', 'environment')
    $Command.Arguments.Kind | Should -Be @('arg', 'for-each')
    $Command.Arguments[1].Arguments[0].Value | Should -Be '{item}'
    $Command.WorkingDirectory.Source | Should -Be 'work'
    $Command.Runner.ResolvedInterface | Should -Be 'https://downloads.example.test/runner.xml'
    $Command.Runner.Arguments[0].Value | Should -Be '--runner'
    $Feed.Protocols | Should -Be @('default-protocol', 'explicit-protocol')
    $Feed.DefaultProtocols | Should -Be @('default-protocol')
    $Feed.FileExtensions | Should -Be @('default', 'explicit')
    $Feed.DefaultFileExtensions | Should -Be @('default')
  }

  It 'rejects namespace spoofing and malformed bounded numeric attributes' {
    { ConvertFrom-ZeroInstallFeed -Content '<interface xmlns="https://example.test/not-zero-install"><name>Fake</name></interface>' } | Should -Throw '*namespaced Zero Install*'
    { ConvertFrom-ZeroInstallFeed -Content '<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface"><name>Bad Size</name><implementation id="sha256new_X" version="1"><archive href="a.zip" size="-1" /></implementation></interface>' } | Should -Throw '*archive.size*'
    { ConvertFrom-ZeroInstallFeed -Content '<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface"><implementation id="sha256new_X" version="1" /></interface>' } | Should -Throw '*required name*'
    { ConvertFrom-ZeroInstallFeed -Content '<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" xmlns:cap="http://0install.de/schema/desktop-integration/capabilities"><name>Bad capability</name><cap:capabilities><cap:url-protocol id="bad/protocol" /></cap:capabilities></interface>' } | Should -Throw '*safe identifier*'
  }
}

Describe 'Zero Install offline implementation materialization' {
  It 'matches source-backed manifest vectors for every supported digest format' {
    $Implementation = Join-Path $TestDrive 'DigestVector'
    $null = New-Item -Path $Implementation -ItemType Directory
    [IO.File]::WriteAllText((Join-Path $Implementation 'file.dat'), 'data', [Text.UTF8Encoding]::new($false))
    (Get-Item -LiteralPath (Join-Path $Implementation 'file.dat')).LastWriteTimeUtc = [DateTimeOffset]::FromUnixTimeSeconds(0).UtcDateTime

    $Vectors = @(
      @{ Algorithm = 'Sha1'; Manifest = "X a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd 0 4 file.dat`n"; Digest = 'sha1=75ea1145050a0acea9782e3078f8984f46e1f42c' }
      @{ Algorithm = 'Sha1New'; Manifest = "X a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd 0 4 file.dat`n"; Digest = 'sha1new=75ea1145050a0acea9782e3078f8984f46e1f42c' }
      @{ Algorithm = 'Sha256'; Manifest = "X 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7 0 4 file.dat`n"; Digest = 'sha256=1296c9dfbeb1f0a7eb7c104f8a556e194e10ad45a75d2c8710def3828c5f08a5' }
      @{ Algorithm = 'Sha256New'; Manifest = "X 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7 0 4 file.dat`n"; Digest = 'sha256new_CKLMTX56WHYKP234CBHYUVLODFHBBLKFU5OSZBYQ33ZYFDC7BCSQ' }
    )
    foreach ($Vector in $Vectors) {
      $Result = Get-ZeroInstallImplementationManifest -Path $Implementation -Algorithm $Vector.Algorithm -ExecutablePath 'file.dat'
      $Result.ManifestText | Should -Be $Vector.Manifest
      $Result.Digest | Should -Be $Vector.Digest
      Test-ZeroInstallImplementationDigest -Path $Implementation -Digest $Vector.Digest -ExecutablePath 'file.dat' | Should -BeTrue
    }
  }

  It 'matches the legacy sha1 directory record and traversal layout' {
    $Implementation = Join-Path $TestDrive 'LegacyDigestVector'
    $Subdirectory = Join-Path $Implementation 'a'
    $null = New-Item -Path $Subdirectory -ItemType Directory -Force
    [IO.File]::WriteAllText((Join-Path $Implementation 'root.dat'), 'root', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $Subdirectory 'child.dat'), 'child', [Text.UTF8Encoding]::new($false))
    foreach ($Path in (Join-Path $Implementation 'root.dat'), (Join-Path $Subdirectory 'child.dat')) {
      (Get-Item -LiteralPath $Path).LastWriteTimeUtc = [DateTimeOffset]::FromUnixTimeSeconds(0).UtcDateTime
    }
    (Get-Item -LiteralPath $Subdirectory).LastWriteTimeUtc = [DateTimeOffset]::FromUnixTimeSeconds(10).UtcDateTime

    $ExpectedManifest = "D 10 /a`nF 0e93069c40111cd62dac2cd02cd71daffdb01cc0 0 5 child.dat`nF dc76e9f0c0006e8f919e0c515c66dbba3982f785 0 4 root.dat`n"
    $Result = Get-ZeroInstallImplementationManifest -Path $Implementation -Algorithm Sha1

    $Result.ManifestText | Should -Be $ExpectedManifest
    $Result.Digest | Should -Be 'sha1=e14aa9a798500380f6bb049e75ca6813a7ea5432'
    Test-ZeroInstallImplementationDigest -Path $Implementation -Digest $Result.Digest | Should -BeTrue
  }

  It 'verifies the official historical sha1 archive vector with directory timestamps' {
    $ArchivePath = Resolve-DumplingsTestFixturePath 'Installers\ZeroInstall\OfficialSource\v0.29\HelloWorld.tgz'
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $ArchivePath -Sha256 '606B8201B919CA7127065602EB9C1D8EF052063CF40CF06341D7959A506F6556')) { Set-ItResult -Skipped -Because 'Cache the Zero Install v0.29 HelloWorld.tgz test vector.'; return }
    $Destination = Join-Path $TestDrive 'LegacyOfficialVector'
    $ArchiveSize = (Get-Item -LiteralPath $ArchivePath).Length
    $Feed = ConvertFrom-ZeroInstallFeed -BaseUri 'https://example.test/hello.xml' -Content @"
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://example.test/hello.xml">
  <name>Hello</name>
  <implementation id="sha1=3ce644dc725f1d21cfcf02562c76f375944b266a" version="1">
    <archive href="HelloWorld.tgz" size="$ArchiveSize" type="application/x-compressed-tar" />
  </implementation>
</interface>
"@

    $Result = Expand-ZeroInstallImplementation -FeedInfo $Feed -ImplementationId 'sha1=3ce644dc725f1d21cfcf02562c76f375944b266a' -RetrievalSource @{'https://example.test/HelloWorld.tgz' = $ArchivePath } -DestinationPath $Destination -CollisionAction Error

    $Result.ManifestVerified | Should -BeTrue
    $Result.CalculatedDigest | Should -Be 'sha1=3ce644dc725f1d21cfcf02562c76f375944b266a'
    $Result.ExecutablePaths | Should -Be @('HelloWorld/main')
  }

  It 'applies archive, file, rename, remove, and copy-from steps in order before verifying the digest' {
    $ArchiveSource = Join-Path $TestDrive 'RecipeArchive'
    $ArchivePath = Join-Path $TestDrive 'recipe.zip'
    $SidecarPath = Join-Path $TestDrive 'sidecar.dat'
    $BaseImplementation = Join-Path $TestDrive 'BaseImplementation'
    $ExpectedPath = Join-Path $TestDrive 'ExpectedImplementation'
    $Destination = Join-Path $TestDrive 'RecipeOutput'
    $null = New-Item -Path (Join-Path $ArchiveSource 'root') -ItemType Directory -Force
    [IO.File]::WriteAllText((Join-Path $ArchiveSource 'root\old.txt'), 'old', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $ArchiveSource 'root\obsolete.txt'), 'remove', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($SidecarPath, 'side', [Text.UTF8Encoding]::new($false))
    $null = New-Item -Path $BaseImplementation -ItemType Directory
    [IO.File]::WriteAllText((Join-Path $BaseImplementation 'tool.exe'), 'tool', [Text.UTF8Encoding]::new($false))
    (Get-Item -LiteralPath (Join-Path $BaseImplementation 'tool.exe')).LastWriteTimeUtc = [DateTimeOffset]::FromUnixTimeSeconds(123).UtcDateTime
    "X ignored 123 4 tool.exe`n" | Set-Content -LiteralPath (Join-Path $BaseImplementation '.manifest') -NoNewline -Encoding utf8NoBOM

    $ArchiveStream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $Archive = [IO.Compression.ZipArchive]::new($ArchiveStream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
      foreach ($Name in 'old.txt', 'obsolete.txt') {
        $Entry = $Archive.CreateEntry("root/$Name")
        $Entry.LastWriteTime = [DateTimeOffset]::new(2001, 2, 3, 4, 5, 6, [TimeSpan]::Zero)
        $InputStream = [IO.File]::OpenRead((Join-Path $ArchiveSource "root\$Name"))
        $OutputStream = $Entry.Open()
        try { $InputStream.CopyTo($OutputStream) } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
      }
    } finally { $Archive.Dispose(); $ArchiveStream.Dispose() }

    $null = New-Item -Path (Join-Path $ExpectedPath 'app') -ItemType Directory -Force
    Copy-Item -LiteralPath (Join-Path $ArchiveSource 'root\old.txt') -Destination (Join-Path $ExpectedPath 'app\new.txt')
    (Get-Item -LiteralPath (Join-Path $ExpectedPath 'app\new.txt')).LastWriteTimeUtc = [datetime]::SpecifyKind([datetime]'2001-02-03T04:05:06', [DateTimeKind]::Utc)
    Copy-Item -LiteralPath $SidecarPath -Destination (Join-Path $ExpectedPath 'app\sidecar.dat')
    (Get-Item -LiteralPath (Join-Path $ExpectedPath 'app\sidecar.dat')).LastWriteTimeUtc = [DateTimeOffset]::FromUnixTimeSeconds(0).UtcDateTime
    Copy-Item -LiteralPath (Join-Path $BaseImplementation 'tool.exe') -Destination (Join-Path $ExpectedPath 'app\tool.exe')
    $Expected = Get-ZeroInstallImplementationManifest -Path $ExpectedPath -Algorithm Sha256New -ExecutablePath 'app/tool.exe'
    $ArchiveSize = (Get-Item -LiteralPath $ArchivePath).Length
    $Feed = ConvertFrom-ZeroInstallFeed -BaseUri 'https://example.test/feed.xml' -Content @"
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://example.test/feed.xml">
  <name>Recipe Test</name>
  <implementation id="$($Expected.Digest)" version="1">
    <recipe>
      <archive href="recipe.zip" size="$ArchiveSize" type="application/zip" extract="root" dest="app" />
      <rename source="app/old.txt" dest="app/new.txt" />
      <remove path="app/obsolete.txt" />
      <file href="sidecar.dat" size="4" dest="app/sidecar.dat" />
      <copy-from id="base" source="tool.exe" dest="app/tool.exe" />
    </recipe>
  </implementation>
</interface>
"@

    $Result = Expand-ZeroInstallImplementation -FeedInfo $Feed -ImplementationId $Expected.Digest -RetrievalSource @{
      'https://example.test/recipe.zip'  = $ArchivePath
      'https://example.test/sidecar.dat' = $SidecarPath
    } -SourceImplementation @{ base = $BaseImplementation } -DestinationPath $Destination -CollisionAction Error

    $Result.ManifestVerified | Should -BeTrue
    $Result.CalculatedDigest | Should -Be $Expected.Digest
    $Result.ExecutablePaths | Should -Be @('app/tool.exe')
    $Result.Files.Name | Sort-Object | Should -Be @('new.txt', 'sidecar.dat', 'tool.exe')
    Test-Path -LiteralPath (Join-Path $Destination 'app\obsolete.txt') | Should -BeFalse
  }

  It 'does not publish files when manifest verification fails' {
    $Payload = Join-Path $TestDrive 'MismatchPayload.dat'
    $Destination = Join-Path $TestDrive 'MismatchDestination'
    $null = New-Item -Path $Destination -ItemType Directory
    [IO.File]::WriteAllText($Payload, 'data', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $Destination 'sentinel.txt'), 'keep', [Text.UTF8Encoding]::new($false))
    $Feed = ConvertFrom-ZeroInstallFeed -BaseUri 'https://example.test/feed.xml' -Content @'
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://example.test/feed.xml">
  <name>Mismatch Test</name>
  <implementation id="sha256new_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" version="1">
    <file href="file.dat" size="4" dest="file.dat" />
  </implementation>
</interface>
'@

    { Expand-ZeroInstallImplementation -FeedInfo $Feed -ImplementationId 'sha256new_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' -RetrievalSource @{'https://example.test/file.dat' = $Payload } -DestinationPath $Destination -CollisionAction Error } | Should -Throw '*digest does not match*'
    (Get-Content -LiteralPath (Join-Path $Destination 'sentinel.txt') -Raw) | Should -Be 'keep'
    Test-Path -LiteralPath (Join-Path $Destination 'file.dat') | Should -BeFalse
  }

  It 'requires an explicit choice when a feed exposes multiple retrieval methods' {
    $FirstPayload = Join-Path $TestDrive 'FirstMethod.dat'
    $SecondPayload = Join-Path $TestDrive 'SecondMethod.dat'
    [IO.File]::WriteAllText($FirstPayload, 'first', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($SecondPayload, 'second', [Text.UTF8Encoding]::new($false))
    $Feed = ConvertFrom-ZeroInstallFeed -BaseUri 'https://example.test/feed.xml' -Content @'
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://example.test/feed.xml">
  <name>Alternative Methods</name>
  <implementation id="sha256new_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" version="1">
    <file href="first.dat" size="5" dest="payload.dat" />
    <file href="second.dat" size="6" dest="payload.dat" />
  </implementation>
</interface>
'@

    { Expand-ZeroInstallImplementation -FeedInfo $Feed -ImplementationId 'sha256new_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' -RetrievalSource @{'https://example.test/first.dat' = $FirstPayload; 'https://example.test/second.dat' = $SecondPayload } -SkipManifestDigestCheck } | Should -Throw '*specify -RetrievalMethodIndex*'
  }

  It 'rejects traversal paths before publishing archive output' {
    $ArchivePath = Join-Path $TestDrive 'Traversal.zip'
    $Destination = Join-Path $TestDrive 'TraversalOutput'
    $ArchiveStream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $Archive = [IO.Compression.ZipArchive]::new($ArchiveStream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
      $Entry = $Archive.CreateEntry('../escape.txt')
      $EntryStream = $Entry.Open()
      try {
        $Bytes = [Text.Encoding]::UTF8.GetBytes('escape')
        $EntryStream.Write($Bytes)
      } finally { $EntryStream.Dispose() }
    } finally { $Archive.Dispose(); $ArchiveStream.Dispose() }
    $Feed = ConvertFrom-ZeroInstallFeed -BaseUri 'https://example.test/feed.xml' -Content @"
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://example.test/feed.xml">
  <name>Traversal Test</name>
  <implementation id="sha256new_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" version="1">
    <archive href="Traversal.zip" size="$((Get-Item -LiteralPath $ArchivePath).Length)" type="application/zip" />
  </implementation>
</interface>
"@

    { Expand-ZeroInstallImplementation -FeedInfo $Feed -ImplementationId 'sha256new_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' -RetrievalSource @{'https://example.test/Traversal.zip' = $ArchivePath } -DestinationPath $Destination -CollisionAction Error -SkipManifestDigestCheck } | Should -Throw '*escapes the destination*'
    Test-Path -LiteralPath $Destination | Should -BeFalse
    Test-Path -LiteralPath (Join-Path $TestDrive 'escape.txt') | Should -BeFalse
  }

  It 'returns an unverified computed manifest only when the caller explicitly permits a digest-less implementation' {
    $Payload = Join-Path $TestDrive 'DigestlessPayload.dat'
    [IO.File]::WriteAllText($Payload, 'data', [Text.UTF8Encoding]::new($false))
    $Feed = ConvertFrom-ZeroInstallFeed -BaseUri 'https://example.test/feed.xml' -Content @'
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://example.test/feed.xml">
  <name>Digestless Test</name>
  <implementation id="custom-id" version="1">
    <file href="file.dat" size="4" dest="file.dat" />
  </implementation>
</interface>
'@

    $Result = Expand-ZeroInstallImplementation -FeedInfo $Feed -ImplementationId 'custom-id' -RetrievalSource @{'https://example.test/file.dat' = $Payload } -SkipManifestDigestCheck -CollisionAction Error
    $Result.ManifestVerified | Should -BeFalse
    $Result.ExpectedDigest | Should -BeNullOrEmpty
    $Result.CalculatedDigest | Should -Match '^sha256new_[A-Z2-7]{52}$'
  }

  It 'streams a non-ZIP archive through the shared managed archive reader' {
    $ArchivePath = Join-Path $TestDrive 'Payload.tar'
    $ArchiveStream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $Writer = [System.Formats.Tar.TarWriter]::new($ArchiveStream, $true)
    try {
      $Entry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, 'root/payload.txt')
      $Entry.ModificationTime = [DateTimeOffset]::FromUnixTimeSeconds(456)
      $Entry.DataStream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('payload'), $false)
      try { $Writer.WriteEntry($Entry) } finally { $Entry.DataStream.Dispose() }
    } finally { $Writer.Dispose(); $ArchiveStream.Dispose() }
    $Feed = ConvertFrom-ZeroInstallFeed -BaseUri 'https://example.test/feed.xml' -Content @"
<interface xmlns="http://zero-install.sourceforge.net/2004/injector/interface" uri="https://example.test/feed.xml">
  <name>TAR Test</name>
  <implementation id="custom-tar" version="1">
    <archive href="Payload.tar" size="$((Get-Item -LiteralPath $ArchivePath).Length)" type="application/x-tar" extract="root" />
  </implementation>
</interface>
"@

    $Result = Expand-ZeroInstallImplementation -FeedInfo $Feed -ImplementationId 'custom-tar' -RetrievalSource @{'https://example.test/Payload.tar' = $ArchivePath } -SkipManifestDigestCheck -CollisionAction Error
    $Result.Files.Name | Should -Be 'payload.txt'
    (Get-Content -LiteralPath $Result.Files[0].FullName -Raw) | Should -Be 'payload'
    [DateTimeOffset]::new($Result.Files[0].LastWriteTimeUtc).ToUnixTimeSeconds() | Should -Be 456
  }
}

Describe 'Zero Install bootstrapper parser' {
  It 'recognizes the authentic 2.11.5 Bootstrap project output built from the tagged source' {
    if (-not (Test-Path -LiteralPath $Script:SourceBuiltLegacyBootstrapper)) { Set-ItResult -Skipped -Because 'the optional source-built historical fixture is not cached'; return }
    (Get-DumplingsTestFixtureHash -Path $Script:SourceBuiltLegacyBootstrapper) | Should -Be '1F0E2CB61793362C625F4EDD1D4EDF753FC7E64E242D87B4094E52A6867C3F84'
    $Info = Get-ZeroInstallInfo -Path $Script:SourceBuiltLegacyBootstrapper

    $Info.FormatGeneration | Should -Be 'LegacyGenericBootstrapper'
    $Info.RuntimeVersion.ToString() | Should -Be '2.11.5.0'
    $Info.LegacyDeploymentBootstrapper | Should -BeTrue
    $Info.InstallerSwitches.Silent | Should -Be '--verysilent'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be '--silent'
  }
  It 'reads the configured DeepL bootstrapper and derives its exact uninstall identity' {
    $Info = Get-ZeroInstallInfo -Path $Script:DeepLInstaller

    $Info.InstallerType | Should -Be 'exe'
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
    $Info.Architectures | Should -Be @('x64')
    $Info.FeedInfo.Implementations | Should -HaveCount 2
    $Info.ApplicableImplementations | Should -HaveCount 1
    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example')
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.Diagnostics.Message | Should -Contain "The supplied feed URI 'https://downloads.example.test/product.xml' does not match embedded app_uri 'https://appdownload.deepl.com/windows/0install/deepl.xml'."
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

  It 'recognizes the source-backed pre-configuration bootstrapper identity without inventing target metadata' {
    $Installer = New-ZeroInstallLegacyIdentityBootstrapper
    $Info = Get-ZeroInstallInfo -Path $Installer

    Test-ZeroInstallInstaller -Path $Installer | Should -BeTrue
    $Info.FormatGeneration | Should -Be 'LegacyGenericBootstrapper'
    $Info.RuntimeVersion | Should -Be ([version]'2.11.5.0')
    $Info.ConfigurationResourceName | Should -BeNullOrEmpty
    $Info.AppUri | Should -BeNullOrEmpty
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.CanExpand | Should -BeFalse
    $Info.InstallModes | Should -Contain 'silent'
    $Info.InstallerSwitches.SilentWithProgress | Should -Be $Info.InstallerSwitches.Silent
    $Info.SupportedCommandLineSwitches | Should -Contain '--verysilent'
    $Info.SupportedCommandLineSwitches | Should -Not -Contain '--content-dir=<PATH>'
    $Info.Diagnostics.Id | Should -Contain 'ZeroInstall.Configuration.LegacyGenericBootstrapper'

    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    ($Analysis.FamilyCandidates | Where-Object Family -EQ 'Zero Install').MatchedMarkers | Should -Contain 'CLR type ZeroInstall.Bootstrap.BootstrapProcess'
    ($Analysis.ParserResults | Where-Object Name -EQ 'Zero Install').Success | Should -BeTrue
  }

  It 'routes every historical configuration generation using official release media' {
    $ExpectedProfiles = [ordered]@{
      '2.16.0'  = 'EmbeddedConfig3Mode'
      '2.21.0'  = 'EmbeddedConfig5Mode'
      '2.22.0'  = 'EmbeddedConfig5Integrate'
      '2.23.0'  = 'EmbeddedConfig6AppFingerprint'
      '2.23.1'  = 'EmbeddedConfig6KeyFingerprint'
      '2.23.3'  = 'EmbeddedConfig6KeyFingerprint'
      '2.24.0'  = 'EmbeddedConfig6KeyFingerprint'
      '2.24.6'  = 'EmbeddedConfig7'
      '2.24.8'  = 'ConfigIni'
      '2.25.12' = 'BootstrapConfigIni'
    }

    foreach ($Entry in $ExpectedProfiles.GetEnumerator()) {
      $Isolated = Join-Path $TestDrive "zero-install-$($Entry.Key)-generic.exe"
      Copy-Item -LiteralPath $Script:HistoricalBootstrappers[$Entry.Key] -Destination $Isolated
      $Info = Get-ZeroInstallInfo -Path $Isolated
      $Info.FormatGeneration | Should -Be $Entry.Value -Because "Zero Install $($Entry.Key) has a distinct source-backed resource layout"
      $Info.Diagnostics.Id | Should -Not -Contain 'ZeroInstall.Configuration.ProfileVersionMismatch'
    }
  }

  It 'applies historical ARP, scope, switch, and display-name boundaries' {
    $Cases = @(
      @{ Version = '2.16.0'; Values = @('https://downloads.example.test/product.xml', 'Example Product', 'integrate'); WritesArp = $false; DualScope = $false; Modes = @('interactive'); ArpName = $null; ArpPublisher = $null }
      @{ Version = '2.21.0'; Values = @('https://downloads.example.test/product.xml', 'Example Product', 'integrate', '--add-all', 'ABCDEF'); WritesArp = $true; DualScope = $false; Modes = @('interactive'); ArpName = 'Example Product (Zero Install)'; ArpPublisher = $null }
      @{ Version = '2.22.0'; Values = @('https://downloads.example.test/product.xml', 'Example Product', 'ABCDEF', '', '--add-all'); WritesArp = $true; DualScope = $false; Modes = @('interactive'); ArpName = 'Example Product (Zero Install)'; ArpPublisher = $null }
      @{ Version = '2.23.0'; Values = @('https://apps.0install.net/0install/0install-win.xml', 'https://downloads.example.test/product.xml', 'Example Product', 'ABCDEF', '', '--add-all'); WritesArp = $true; DualScope = $false; Modes = @('interactive', 'silentWithProgress'); ArpName = 'Example Product (Zero Install)'; ArpPublisher = $null }
      @{ Version = '2.23.1'; Values = @('https://apps.0install.net/0install/0install-win.xml', 'ABCDEF', 'https://downloads.example.test/product.xml', 'Example Product', '', '--add-all'); WritesArp = $true; DualScope = $true; Modes = @('interactive', 'silentWithProgress'); ArpName = 'Example Product (Zero Install)'; ArpPublisher = $null }
      @{ Version = '2.23.3'; Values = @('https://apps.0install.net/0install/0install-win.xml', 'ABCDEF', 'https://downloads.example.test/product.xml', 'Example Product', '', '--add-all'); WritesArp = $true; DualScope = $true; Modes = @('interactive', 'silentWithProgress'); ArpName = 'Example Product'; ArpPublisher = $null }
      @{ Version = '2.24.0'; Values = @('https://apps.0install.net/0install/0install-win.xml', 'ABCDEF', 'https://downloads.example.test/product.xml', 'Example Product', '', '--add-all'); WritesArp = $true; DualScope = $true; Modes = @('interactive', 'silent', 'silentWithProgress'); ArpName = 'Example Product'; ArpPublisher = 'Example Publisher' }
      @{ Version = '2.24.6'; Values = @('https://apps.0install.net/0install/0install-win.xml', 'ABCDEF', 'https://downloads.example.test/product.xml', 'Example Product', '', '--add-all', 'true'); WritesArp = $true; DualScope = $true; Modes = @('interactive', 'silent', 'silentWithProgress'); ArpName = 'Example Product'; ArpPublisher = 'Example Publisher' }
    )

    foreach ($Case in $Cases) {
      $Installer = New-ZeroInstallFixedLineBootstrapper -Version $Case.Version -Values $Case.Values
      $Info = Get-ZeroInstallInfo -Path $Installer -FeedContent $Script:FeedContent
      $Info.WritesAppsAndFeaturesEntry | Should -Be $Case.WritesArp -Because "Zero Install $($Case.Version) has a source-backed ARP boundary"
      $Info.SupportsDualScope | Should -Be $Case.DualScope
      $Info.InstallModes | Should -Be $Case.Modes
      if ($Info.InstallModes -contains 'silent' -and $Info.InstallModes -notcontains 'silentWithProgress') {
        $Info.InstallerSwitches.SilentWithProgress | Should -Be $Info.InstallerSwitches.Silent
      }
      if ($Case.WritesArp) {
        $Info.ProductCode | Should -Be 'https%3a##downloads.example.test#product.xml'
        $Info.AppsAndFeaturesEvidence.DisplayName | Should -Be $Case.ArpName
        $Info.AppsAndFeaturesEvidence.Publisher | Should -Be $Case.ArpPublisher
      } else {
        $Info.ProductCode | Should -BeNullOrEmpty
        $Info.UninstallKeyNameCandidate | Should -Be 'https%3a##downloads.example.test#product.xml'
      }
      if ([version]$Case.Version -lt [version]'2.24.8') { $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'InstallLocation' }
    }
  }

  It 'uses adjacent INI configuration and honors the store-path and ARP modify boundaries' {
    $Configuration = @'
[bootstrap]
app_uri=https://downloads.example.test/product.xml
app_name=Example Product
integrate_args=--add-all
customizable_store_path=true
[global]
self_update_uri=https://apps.0install.net/0install/0install-win.xml
'@
    $BeforeModify = Get-ZeroInstallInfo -Path (New-ZeroInstallIniBootstrapper -Version '2.24.8' -Content $Configuration) -FeedContent $Script:FeedContent
    $AfterModify = Get-ZeroInstallInfo -Path (New-ZeroInstallIniBootstrapper -Version '2.25.12' -Content $Configuration) -FeedContent $Script:FeedContent

    $BeforeModify.ConfigurationSource | Should -Match '^Adjacent INI:'
    $BeforeModify.InstallerSwitches.InstallLocation | Should -Be '--store-path="<INSTALLPATH>"'
    $BeforeModify.AppsAndFeaturesEvidence.NoModify | Should -Be 1
    $BeforeModify.AppsAndFeaturesEvidence.ModifyArguments | Should -BeNullOrEmpty
    $AfterModify.AppsAndFeaturesEvidence.NoModify | Should -Be 0
    $AfterModify.AppsAndFeaturesEvidence.ModifyArguments | Should -Be @('integrate', 'https://downloads.example.test/product.xml')
  }

  It 'does not turn a bound run-only bootstrapper into ARP evidence' {
    $Installer = New-ZeroInstallFixedLineBootstrapper -Version '2.24.0' -Values @(
      'https://apps.0install.net/0install/0install-win.xml',
      'ABCDEF',
      'https://downloads.example.test/product.xml',
      'Example Product',
      '',
      ''
    )

    $Info = Get-ZeroInstallInfo -Path $Installer -FeedContent $Script:FeedContent

    $Info.AppUri | Should -Be 'https://downloads.example.test/product.xml'
    $Info.IntegrationConfigured | Should -BeFalse
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.Scope | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.UninstallKeyNameCandidate | Should -Be 'https%3a##downloads.example.test#product.xml'
    $Info.Diagnostics.Id | Should -Contain 'ZeroInstall.Arp.IntegrationNotConfigured'
  }

  It 'projects only capability categories selected by the compiled integration arguments' {
    $AddAll = New-ZeroInstallFixedLineBootstrapper -Version '2.24.0' -Values @(
      'https://apps.0install.net/0install/0install-win.xml', 'ABCDEF',
      'https://downloads.example.test/rich.xml', 'Rich Product', '', '--add-all'
    )
    $AllInfo = Get-ZeroInstallInfo -Path $AddAll -FeedContent $Script:RichFeedContent
    $AddDefaults = New-ZeroInstallFixedLineBootstrapper -Version '2.24.0' -Values @(
      'https://apps.0install.net/0install/0install-win.xml', 'ABCDEF',
      'https://downloads.example.test/rich.xml', 'Rich Product', '', '--add=defaults'
    )
    $DefaultInfo = Get-ZeroInstallInfo -Path $AddDefaults -FeedContent $Script:RichFeedContent

    $AllInfo.Protocols | Should -Be @('default-protocol', 'explicit-protocol')
    $AllInfo.FileExtensions | Should -Be @('default', 'explicit')
    $DefaultInfo.Protocols | Should -Be @('default-protocol')
    $DefaultInfo.FileExtensions | Should -Be @('default')
    $DefaultInfo.AvailableProtocols | Should -Be @('default-protocol', 'explicit-protocol')
    $DefaultInfo.AvailableFileExtensions | Should -Be @('default', 'explicit')
  }

  It 'keeps associations unresolved when integration opens the category-selection UI' {
    $Installer = New-ZeroInstallFixedLineBootstrapper -Version '2.21.0' -Values @(
      'https://downloads.example.test/rich.xml', 'Rich Product', 'integrate', '', 'ABCDEF'
    )
    $Info = Get-ZeroInstallInfo -Path $Installer -FeedContent $Script:RichFeedContent

    $Info.IntegrationConfigured | Should -BeTrue
    $Info.IntegrationSelection.IsDeterministic | Should -BeFalse
    $Info.Protocols | Should -BeNullOrEmpty
    $Info.FileExtensions | Should -BeNullOrEmpty
    $Info.AvailableProtocols | Should -Be @('default-protocol', 'explicit-protocol')
    $Info.Diagnostics.Id | Should -Contain 'ZeroInstall.Associations.IntegrationSelectionUnresolved'
    $Info.UnresolvedFields | Should -Contain 'Protocols'
    $Info.UnresolvedFields | Should -Contain 'FileExtensions'
  }

  It 'treats compiled machine integration as fixed scope' {
    $Installer = New-ZeroInstallFixedLineBootstrapper -Version '2.24.0' -Values @(
      'https://apps.0install.net/0install/0install-win.xml',
      'ABCDEF',
      'https://downloads.example.test/product.xml',
      'Example Product',
      '',
      '--add-all --machine'
    )

    $Info = Get-ZeroInstallInfo -Path $Installer -FeedContent $Script:FeedContent

    $Info.Scope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.ScopeSwitches | Should -BeNullOrEmpty
    $Info.AppsAndFeaturesEvidence.Hive | Should -Be 'HKEY_LOCAL_MACHINE'
    $Info.AppsAndFeaturesEvidence.UninstallArguments | Should -Be @('remove', 'https://downloads.example.test/product.xml', '--machine')
  }

  It 'requires an exact Windows argument token before fixing machine scope' {
    $FalsePositive = New-ZeroInstallFixedLineBootstrapper -Version '2.24.0' -Values @(
      'https://apps.0install.net/0install/0install-win.xml',
      'ABCDEF',
      'https://downloads.example.test/product.xml',
      'Example Product',
      '',
      '--add-all --machine-wide "value --machine"'
    )
    $UserInfo = Get-ZeroInstallInfo -Path $FalsePositive -FeedContent $Script:FeedContent
    $ExactQuoted = New-ZeroInstallFixedLineBootstrapper -Version '2.24.0' -Values @(
      'https://apps.0install.net/0install/0install-win.xml',
      'ABCDEF',
      'https://downloads.example.test/product.xml',
      'Example Product',
      '',
      '--add-all "--machine"'
    )

    $MachineInfo = Get-ZeroInstallInfo -Path $ExactQuoted -FeedContent $Script:FeedContent

    $UserInfo.IntegrateArgumentList | Should -Be @('--add-all', '--machine-wide', 'value --machine')
    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.SupportsDualScope | Should -BeTrue
    $MachineInfo.IntegrateArgumentList | Should -Be @('--add-all', '--machine')
    $MachineInfo.Scope | Should -Be 'machine'
  }

  It 'exports historical fixed-line configuration under a stable name' {
    $Destination = Join-Path $TestDrive 'HistoricalZeroInstallExpansion'
    $Files = @(Expand-ZeroInstallInstaller -Path $Script:HistoricalBootstrappers['2.16.0'] -DestinationPath $Destination -Name 'EmbeddedConfig.txt' -CollisionAction Rename)

    $Files | Should -HaveCount 1
    $Files[0].Name | Should -Be 'EmbeddedConfig.txt'
    (Get-Content -LiteralPath $Files[0].FullName -Raw) | Should -Match 'AppUri'
  }

  It 'does not inherit current WinGet defaults for a historical bootstrapper' {
    $Installer = New-ZeroInstallFixedLineBootstrapper -Version '2.16.0' -Values @('https://downloads.example.test/product.xml', 'Example Product', 'integrate')
    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object Name -EQ 'Zero Install' | Select-Object -First 1

    $Result.Success | Should -BeTrue
    $Result.Result.SuggestedManifestFields.InstallModes | Should -Be @('interactive')
    $Result.Result.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'ProductCode'
    $Result.Result.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'Scope'
    $Result.Result.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'InstallerSwitches'
    $Result.Result.SuggestedManifestVariants | Should -BeNullOrEmpty
  }

  It 'applies historical appSettings overrides after their source introduction' {
    $Installer = New-ZeroInstallFixedLineBootstrapper -Version '2.16.0' -Values @('https://downloads.example.test/original.xml', 'Original Product', 'run')
    @'
<configuration>
  <appSettings>
    <add key="app_uri" value="https://downloads.example.test/product.xml" />
    <add key="app_name" value="Example Product" />
    <add key="app_mode" value="integrate" />
  </appSettings>
</configuration>
'@ | Set-Content -LiteralPath "$Installer.config" -Encoding utf8NoBOM

    $Info = Get-ZeroInstallInfo -Path $Installer -FeedContent $Script:FeedContent

    $Info.ConfigurationSource | Should -Match 'adjacent application configuration'
    $Info.AppUri | Should -Be 'https://downloads.example.test/product.xml'
    $Info.AppName | Should -Be 'Example Product'
    $Info.AppMode | Should -Be 'integrate'
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
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
    $Info.Diagnostics.Message | Should -Contain 'The adjacent INI overrides the embedded bootstrap configuration at runtime; ensure the package delivers both files together.'
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
    $Files = @(Expand-ZeroInstallInstaller -Path $Script:DeepLInstaller -DestinationPath $Destination -Name 'BootstrapConfig.ini' -CollisionAction Rename)

    $Files | Should -HaveCount 1
    $Files[0].Name | Should -Be 'BootstrapConfig.ini'
    (Get-Content -LiteralPath $Files[0].FullName -Raw) | Should -Match '(?m)^app_uri\s*=\s*https://appdownload\.deepl\.com/windows/0install/deepl\.xml\r?$'
  }

  It 'classifies embedded stubs and expands explicitly supplied implementation archives on request' {
    $DeepLInfo = Get-ZeroInstallInfo -Path $Script:DeepLInstaller
    $DeepLInfo.ContentEntries | Should -HaveCount 3
    $DeepLInfo.ContentEntries.Kind | Should -Not -Contain 'ImplementationArchive'
    $DeepLInfo.ContentEntries.Kind | Select-Object -Unique | Should -Be 'StubExecutable'

    $ContentDirectory = Join-Path $TestDrive 'ZeroInstallContent'
    $PayloadDirectory = Join-Path $TestDrive 'ZeroInstallPayload'
    $null = New-Item -Path (Join-Path $PayloadDirectory 'bin') -ItemType Directory -Force
    Set-Content -LiteralPath (Join-Path $PayloadDirectory 'bin\app.txt') -Value 'payload' -NoNewline
    $Digest = 'sha256=' + ('a' * 64)
    $ArchivePath = Join-Path $ContentDirectory "$Digest.zip"
    $null = New-Item -Path $ContentDirectory -ItemType Directory -Force
    [IO.Compression.ZipFile]::CreateFromDirectory($PayloadDirectory, $ArchivePath)

    $Info = Get-ZeroInstallInfo -Path $Script:DeepLInstaller -ContentDirectoryPath $ContentDirectory
    $Entry = $Info.ContentEntries | Where-Object ManifestDigest -EQ $Digest
    $Entry.Kind | Should -Be 'ImplementationArchive'
    $Entry.Source | Should -Be 'ContentDirectory'
    $Info.Diagnostics.Id | Should -Contain 'ZeroInstall.Content.ManifestDigestNotVerified'
    $Info.UnresolvedFields | Should -Contain 'PayloadIntegrity'

    $Destination = Join-Path $TestDrive 'ZeroInstallImplementationExpansion'
    $Files = @(Expand-ZeroInstallInstaller -Path $Script:DeepLInstaller -DestinationPath $Destination -ContentDirectoryPath $ContentDirectory -ExpandImplementationArchives -Name "_implementations/$Digest/*" -CollisionAction Rename)
    $Files | Should -HaveCount 1
    $Files[0].FullName | Should -Be (Join-Path $Destination "_implementations\$Digest\bin\app.txt")
    (Get-Content -LiteralPath $Files[0].FullName -Raw) | Should -Be 'payload'
  }

  It 'rejects a managed PE without Zero Install bootstrap configuration' {
    Test-ZeroInstallInstaller -Path (Get-Process -Id $PID).Path | Should -BeFalse
  }

  It 'keeps structural detection independent from malformed adjacent overrides' {
    $Installer = Join-Path $TestDrive 'MalformedSidecar.exe'
    Copy-Item -LiteralPath $Script:DeepLInstaller -Destination $Installer
    Set-Content -LiteralPath ([IO.Path]::ChangeExtension($Installer, '.ini')) -Value '[wrong-section]' -Encoding utf8NoBOM

    Test-ZeroInstallInstaller -Path $Installer | Should -BeTrue
    { Get-ZeroInstallInfo -Path $Installer } | Should -Throw '*has no *bootstrap* section*'
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
    ($Result.Result.SuggestedManifestVariants | Where-Object Name -EQ machine).ManifestFields.InstallerSwitches.Custom | Should -Be '--machine'
  }
}
