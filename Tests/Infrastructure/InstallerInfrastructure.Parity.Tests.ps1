. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallerInfrastructureTestSetup.ps1')

Describe 'Shared installer infrastructure parity' {
  It 'keeps common sources and archive assets byte-identical' {
    $PackageRoot = $Script:DumplingsModuleRoot
    $ParserRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..\InstallerParsers'))
    $PathPairs = @(
      @{ Package = 'Libraries\Infrastructure\Runtime.psm1'; Parser = 'Libraries\Infrastructure\Runtime.psm1' }
      @{ Package = 'Libraries\Infrastructure\Binary.psm1'; Parser = 'Libraries\Infrastructure\Binary.psm1' }
      @{ Package = 'Libraries\Infrastructure\Archive.psm1'; Parser = 'Libraries\Infrastructure\Archive.psm1' }
      @{ Package = 'Libraries\Infrastructure\PE.psm1'; Parser = 'Libraries\Infrastructure\PE.psm1' }
      @{ Package = 'Libraries\Infrastructure\InstallerDiagnostics.psm1'; Parser = 'Libraries\Infrastructure\InstallerDiagnostics.psm1' }
      @{ Package = 'Libraries\Infrastructure\InstallerEvidence.psm1'; Parser = 'Libraries\Infrastructure\InstallerEvidence.psm1' }
      @{ Package = 'Assets\Source\InstallerInfrastructure\BinaryIO.cs'; Parser = 'Assets\Source\InstallerInfrastructure\BinaryIO.cs' }
      @{ Package = 'Assets\Source\InstallerInfrastructure\PatternSearch.cs'; Parser = 'Assets\Source\InstallerInfrastructure\PatternSearch.cs' }
      @{ Package = 'Assets\Source\InstallerInfrastructure\PEImageReader.cs'; Parser = 'Assets\Source\InstallerInfrastructure\PEImageReader.cs' }
      @{ Package = 'Assets\Assemblies\SharpCompress.dll'; Parser = 'Assets\Assemblies\SharpCompress.dll' }
      @{ Package = 'Assets\Assemblies\ZstdSharp.dll'; Parser = 'Assets\Assemblies\ZstdSharp.dll' }
      @{ Package = 'Tests\Support\TestFixture.ps1'; Parser = 'Tests\Support\TestFixture.ps1' }
    )
    foreach ($Pair in $PathPairs) {
      (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PackageRoot $Pair.Package)).Hash |
        Should -Be (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ParserRoot $Pair.Parser)).Hash
    }
  }

  It 'loads process-wide C# types safely from concurrent runspaces' {
    $RuntimeModule = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1'))
    $ScriptPath = Join-Path $TestDrive 'ConcurrentRuntimeLoad.ps1'
    @'
param([string]$RuntimeModule)
$Jobs = 1..8 | ForEach-Object {
  Start-ThreadJob -ScriptBlock {
    param($ModulePath)
    Import-Module -Name $ModulePath -Force
    Import-InstallerInfrastructure
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.InstallerInfrastructure.PEImageReader').Type) {
      throw 'The shared PEImageReader type was not loaded'
    }
  } -ArgumentList $RuntimeModule
}

$Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction Stop
'@ | Set-Content -LiteralPath $ScriptPath

    & (Get-Process -Id $PID).Path -NoProfile -File $ScriptPath -RuntimeModule $RuntimeModule
    $LASTEXITCODE | Should -Be 0
  }

  It 'compiles a related managed source set once under concurrent calls' {
    $SourceDirectory = Join-Path $TestDrive 'ManagedSource'
    $null = New-Item -Path $SourceDirectory -ItemType Directory
    $FirstSource = Join-Path $SourceDirectory 'Model.cs'
    $SecondSource = Join-Path $SourceDirectory 'Reader.cs'
    [IO.File]::WriteAllText($FirstSource, 'namespace Dumplings.Tests.ManagedSourceSet { public sealed partial class Marker { public static string Model => "model"; } }')
    [IO.File]::WriteAllText($SecondSource, 'namespace Dumplings.Tests.ManagedSourceSet { public sealed partial class Marker { public static string Reader => "reader"; } }')
    $RuntimeModule = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1'))

    $Jobs = 1..8 | ForEach-Object {
      Start-ThreadJob -ArgumentList $RuntimeModule, $FirstSource, $SecondSource -ScriptBlock {
        param($ModulePath, $First, $Second)
        Import-Module $ModulePath -Force
        (Import-InstallerManagedSource -Path @($First, $Second) -TypeName 'Dumplings.Tests.ManagedSourceSet.Marker').FullName
      }
    }
    $Assemblies = @($Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction Stop)

    $Assemblies | Select-Object -Unique | Should -HaveCount 1
    [Dumplings.Tests.ManagedSourceSet.Marker]::Model | Should -Be 'model'
    [Dumplings.Tests.ManagedSourceSet.Marker]::Reader | Should -Be 'reader'
  }

  It 'prevents parser-local whole-file buffers and decoder constructors' {
    $Roots = @(
      [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot 'Libraries')),
      [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..\InstallerParsers\Libraries'))
    )
    $Violations = [Collections.Generic.List[string]]::new()
    foreach ($Root in $Roots) {
      foreach ($File in Get-ChildItem -LiteralPath $Root -Include '*.psm1', '*.ps1' -Recurse -File) {
        if ($File.Name -eq 'Archive.psm1') { continue }
        $Text = Get-Content -LiteralPath $File.FullName -Raw
        if ($Text -match '(?i)ReadAllBytes\s*\(') { $Violations.Add("$($File.FullName): unbounded ReadAllBytes") }
        if ($Text -match '\[(?:IO|System\.IO)\.Compression\.(?:ZLibStream|DeflateStream)|SharpCompress\.Compressors\.(?:LZMA\.LzmaStream|BZip2\.BZip2Stream)') {
          $Violations.Add("$($File.FullName): parser-local decoder construction")
        }
      }
    }
    $Violations | Should -BeNullOrEmpty
  }
}

Describe 'Aggregate parser result ownership' {
  It 'keeps canonical result construction in format parsers' {
    $Roots = @(
      [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot 'Libraries')),
      [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..\InstallerParsers\Libraries'))
    )

    foreach ($Root in $Roots) {
      Test-Path -LiteralPath (Join-Path $Root 'InstallerMetadata.psm1') | Should -BeFalse
      Get-ChildItem -LiteralPath $Root -Filter '*.psm1' -Recurse -File |
        Select-String -Pattern 'Complete-InstallerParserInfo' |
        Should -BeNullOrEmpty
    }
  }
}
