# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\InstallerCondition.psm1') -Force
  if (-not ([Management.Automation.PSTypeName]'Dumplings.Tests.VirtualLargeReadStream').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;

namespace Dumplings.Tests
{
    // Exposes a small real prefix followed by sparse zero bytes so tests can
    // model multi-gigabyte PE overlays without allocating or writing them.
    public sealed class VirtualLargeReadStream : Stream
    {
        private readonly byte[] prefix;
        private readonly long length;
        private long position;

        public VirtualLargeReadStream(byte[] prefix, long length)
        {
            this.prefix = prefix ?? throw new ArgumentNullException(nameof(prefix));
            if (length < prefix.LongLength) throw new ArgumentOutOfRangeException(nameof(length));
            this.length = length;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position
        {
            get => position;
            set
            {
                if (value < 0 || value > length) throw new ArgumentOutOfRangeException(nameof(value));
                position = value;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException();
            if (position >= length || count == 0) return 0;

            int total = (int)Math.Min((long)count, length - position);
            int fromPrefix = position < prefix.LongLength
                ? (int)Math.Min((long)total, prefix.LongLength - position)
                : 0;
            if (fromPrefix > 0) Buffer.BlockCopy(prefix, checked((int)position), buffer, offset, fromPrefix);
            if (fromPrefix < total) Array.Clear(buffer, offset + fromPrefix, total - fromPrefix);
            position += total;
            return total;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long next = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(position + offset),
                SeekOrigin.End => checked(length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            Position = next;
            return position;
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
'@
  }
  $Script:TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) 'DumplingsCommonInstallerInfrastructureTests'
  $null = New-Item -ItemType Directory -Path $Script:TemporaryRoot -Force
}

AfterAll {
  if (Test-Path -LiteralPath $Script:TemporaryRoot) { Remove-Item -LiteralPath $Script:TemporaryRoot -Recurse -Force }
}

Describe 'Shared installer infrastructure parity' {
  It 'keeps common sources and archive assets byte-identical' {
    $PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $ParserRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\InstallerParsers'))
    $PathPairs = @(
      @{ Package = 'Libraries\Runtime.psm1'; Parser = 'Libraries\Runtime.psm1' }
      @{ Package = 'Libraries\Binary.psm1'; Parser = 'Libraries\Binary.psm1' }
      @{ Package = 'Libraries\Compression.psm1'; Parser = 'Libraries\Compression.psm1' }
      @{ Package = 'Libraries\Archive.psm1'; Parser = 'Libraries\Archive.psm1' }
      @{ Package = 'Libraries\PE.psm1'; Parser = 'Libraries\PE.psm1' }
      @{ Package = 'Libraries\RegistryAssociations.psm1'; Parser = 'Libraries\RegistryAssociations.psm1' }
      @{ Package = 'Assets\Source\InstallerInfrastructure\BinaryIO.cs'; Parser = 'Assets\InstallerInfrastructure\BinaryIO.cs' }
      @{ Package = 'Assets\Source\InstallerInfrastructure\PatternSearch.cs'; Parser = 'Assets\InstallerInfrastructure\PatternSearch.cs' }
      @{ Package = 'Assets\Source\InstallerInfrastructure\PEImageReader.cs'; Parser = 'Assets\InstallerInfrastructure\PEImageReader.cs' }
      @{ Package = 'Assets\Assemblies\SharpCompress.dll'; Parser = 'Assets\SharpCompress.dll' }
      @{ Package = 'Assets\Assemblies\ZstdSharp.dll'; Parser = 'Assets\ZstdSharp.dll' }
      @{ Package = 'Tests\TestFixture.ps1'; Parser = 'Tests\TestFixture.ps1' }
    )
    foreach ($Pair in $PathPairs) {
      (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PackageRoot $Pair.Package)).Hash |
        Should -Be (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ParserRoot $Pair.Parser)).Hash
    }
  }

  It 'loads process-wide C# types safely from concurrent runspaces' {
    $RuntimeModule = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1'))
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
    $RuntimeModule = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1'))

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
      [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Libraries')),
      [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\InstallerParsers\Libraries'))
    )
    $Violations = [Collections.Generic.List[string]]::new()
    foreach ($Root in $Roots) {
      foreach ($File in Get-ChildItem -LiteralPath $Root -Include '*.psm1', '*.ps1' -Recurse -File) {
        if ($File.Name -eq 'Compression.psm1') { continue }
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
      [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Libraries')),
      [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\InstallerParsers\Libraries'))
    )

    foreach ($Root in $Roots) {
      Test-Path -LiteralPath (Join-Path $Root 'InstallerMetadata.psm1') | Should -BeFalse
      Get-ChildItem -LiteralPath $Root -Filter '*.psm1' -File |
        Select-String -Pattern 'Complete-InstallerParserInfo' |
        Should -BeNullOrEmpty
    }
  }
}

Describe 'Get-InstallerRegistryAssociationInfo' {
  It 'reads literal protocol, ProgID, and OpenWithProgids evidence' {
    $Writes = @(
      [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Classes\example'; Name = $null; Value = 'Example protocol'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Classes\example'; Name = 'URL Protocol'; Value = ''; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Classes\example\shell\open\command'; Name = $null; Value = '"<InstallLocation>\Example.exe" "%1"'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\.example'; Name = $null; Value = 'Example.Document'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\.example\OpenWithProgids'; Name = 'Example.AlternateDocument'; Value = ''; Type = 'REG_NONE' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\Example.Document'; Name = $null; Value = 'Example document'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\Example.Document\shell\open\command'; Name = $null; Value = '"<InstallLocation>\Example.exe" "%1"'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Example'; Name = 'URL Protocol'; Value = ''; Type = 'REG_SZ' }
    )

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example')
    $Info.ProtocolAssociations[0].Command | Should -Be '"<InstallLocation>\Example.exe" "%1"'
    $Info.FileExtensionAssociations[0].ProgIds | Should -Be @('Example.Document', 'Example.AlternateDocument')
    $Info.FileExtensionAssociations[0].Command | Should -Be '"<InstallLocation>\Example.exe" "%1"'
  }

  It 'requires URL Protocol evidence and ignores dynamic class keys' {
    $Writes = @(
      [pscustomobject]@{ Root = 'HKCR'; Key = 'not-a-protocol'; Name = $null; Value = 'Not a protocol'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\{code:Protocol}'; Name = 'URL Protocol'; Value = ''; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 0; Key = '.sample'; Name = $null; Value = 'Sample.Document'; Type = 'REG_SZ' }
    )

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Info.Protocols | Should -BeNullOrEmpty
    $Info.FileExtensions | Should -Be @('sample')
    $Info.Warnings | Should -Contain "Ignored non-literal protocol key '{code:Protocol}'."
  }

  It 'accepts a direct extension shell command without a ProgID' {
    $Writes = @(
      [pscustomobject]@{ Root = 'HKCR'; Key = '.wxproj'; Name = $null; Value = ''; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCR'; Key = '.wxproj\DefaultIcon'; Name = $null; Value = '<InstallLocation>\DevTools.exe'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCR'; Key = '.wxproj\shell\Open\command'; Name = $null; Value = '"<InstallLocation>\DevTools.exe" "%1"'; Type = 'REG_SZ' }
    )

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Info.FileExtensions | Should -Be @('wxproj')
    $Info.FileExtensionAssociations[0].ProgIds | Should -BeNullOrEmpty
    $Info.FileExtensionAssociations[0].Command | Should -Be '"<InstallLocation>\DevTools.exe" "%1"'
    $Info.FileExtensionAssociations[0].DefaultIcon | Should -Be '<InstallLocation>\DevTools.exe'
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'warns when an extension has neither a ProgID nor a direct command' {
    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite @(
      [pscustomobject]@{ Root = 'HKCR'; Key = '.incomplete'; Name = $null; Value = ''; Type = 'REG_SZ' }
    )

    $Info.Warnings | Should -Contain "File extension '.incomplete' has neither a literal ProgID nor a direct open command."
  }
}

Describe 'Find-BinaryPattern' {
  It 'finds overlapping matches and honors match limits' {
    $Bytes = [Text.Encoding]::ASCII.GetBytes('AAAAA')
    @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes('AAA'))) | Should -Be @(0, 1, 2)
    @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes('AA')) -Maximum 2) | Should -Be @(0, 1)
  }

  It 'finds a match spanning the scanner chunk boundary and supports reverse order' {
    $Path = Join-Path $Script:TemporaryRoot 'boundary.bin'
    $Bytes = [byte[]]::new(1048584)
    [Text.Encoding]::ASCII.GetBytes('PATTERN').CopyTo($Bytes, 1048573)
    [Text.Encoding]::ASCII.GetBytes('PATTERN').CopyTo($Bytes, 10)
    [IO.File]::WriteAllBytes($Path, $Bytes)
    @(Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes('PATTERN'))) | Should -Be @(10, 1048573)
    @(Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes('PATTERN')) -Reverse) | Should -Be @(1048573, 10)
    @(Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes('PATTERN')) -Reverse -Maximum 1) | Should -Be @(1048573)
  }

  It 'rejects malformed scan ranges' {
    { Find-BinaryPattern -Bytes ([byte[]](1, 2, 3)) -Pattern ([byte[]](1)) -StartOffset 4 } | Should -Throw
  }

  It 'searches caller-owned streams with alignment and restores position' {
    $Stream = [IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes('----MATCH---MATCH'))
    $Stream.Position = 3
    try {
      @(Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::ASCII.GetBytes('MATCH')) -Alignment 4) | Should -Be @(4, 12)
      $Stream.Position | Should -Be 3
    } finally { $Stream.Dispose() }
  }
}

Describe 'Bounded binary streams' {
  It 'returns byte arrays without pipeline boxing and restores random-access positions' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3, 4))
    $Source.Position = 4
    try {
      $Bytes = Read-BinaryBytes -Stream $Source -Offset 1 -Count 3
      $Bytes.GetType() | Should -Be ([byte[]])
      $Bytes | Should -Be ([byte[]](1, 2, 3))
      $Source.Position | Should -Be 4
    } finally { $Source.Dispose() }
  }

  It 'limits a substream and leaves caller-owned streams open' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3, 4, 5))
    $Range = New-BoundedReadStream -Stream $Source -Offset 2 -Length 3 -LeaveOpen
    try {
      $Output = [byte[]]::new(4)
      $Range.Read($Output, 0, $Output.Length) | Should -Be 3
      $Output[0..2] | Should -Be @(2, 3, 4)
      $Range.ReadByte() | Should -Be -1
    } finally { $Range.Dispose() }
    $Source.CanRead | Should -BeTrue
    $Source.Dispose()
  }

  It 'spills non-seekable nested content to an automatically deleted file' {
    $Raw = [byte[]]::new(32768)
    for ($Index = 0; $Index -lt $Raw.Length; $Index++) { $Raw[$Index] = $Index % 251 }
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.GZipStream]::new($Compressed, [IO.Compression.CompressionMode]::Compress, $true)
    $Encoder.Write($Raw, 0, $Raw.Length)
    $Encoder.Dispose()
    $Compressed.Position = 0
    $Decoder = [IO.Compression.GZipStream]::new($Compressed, [IO.Compression.CompressionMode]::Decompress, $true)
    $Context = New-InstallerSeekableStream -SourceStream $Decoder -MaximumBytes 65536 -MemoryThresholdBytes 1024
    $TemporaryPath = $Context.TemporaryPath
    try {
      $Context.Length | Should -Be $Raw.Length
      $TemporaryPath | Should -Not -BeNullOrEmpty
      $TemporaryPath | Should -Exist
    } finally {
      $Context.Dispose()
      $Decoder.Dispose()
      $Compressed.Dispose()
    }
    $TemporaryPath | Should -Not -Exist
  }

  It 'bounds seekable nested content from the caller current position' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3, 4))
    $Source.Position = 2
    $Context = New-InstallerSeekableStream -SourceStream $Source -MaximumBytes 3
    try {
      $Context.Length | Should -Be 3
      $Context.Stream.ReadByte() | Should -Be 2
    } finally { $Context.Dispose() }
    $Source.CanRead | Should -BeTrue
    $Source.Dispose()
  }

  It 'rejects seekable content that exceeds the spool limit' {
    $Source = [IO.MemoryStream]::new([byte[]](0, 1, 2, 3))
    try { { New-InstallerSeekableStream -SourceStream $Source -MaximumBytes 3 } | Should -Throw }
    finally { $Source.Dispose() }
  }

  It 'computes the standard CRC32 vector and enforces copy limits' {
    $CrcBytes = [Text.Encoding]::ASCII.GetBytes('__123456789__')
    Get-BinaryCrc32 -Bytes $CrcBytes -Offset 2 -Count 9 | Should -Be ([uint32]3421780262)
    Get-BinaryCrc32 -Bytes $CrcBytes | Should -Not -Be ([uint32]3421780262)
    { Get-BinaryCrc32 -Bytes $CrcBytes -Offset 8 -Count 6 } | Should -Throw
    $Source = [IO.MemoryStream]::new([byte[]](1, 2, 3))
    $Destination = [IO.MemoryStream]::new()
    try { { Copy-BoundedStream -Source $Source -Destination $Destination -MaximumBytes 2 } | Should -Throw }
    finally { $Destination.Dispose(); $Source.Dispose() }
  }

  It 'copies and decodes a bounded fixed-XOR stream' {
    $Source = [IO.MemoryStream]::new([byte[]](0xC0, 0xED, 0xE4, 0xE4, 0xE7))
    $Destination = [IO.MemoryStream]::new()
    try {
      Copy-BinaryXorStream -Source $Source -Destination $Destination -Key 0x88 -ExpectedBytes 5 | Should -Be 5
      [Text.Encoding]::ASCII.GetString($Destination.ToArray()) | Should -Be 'Hello'
    } finally {
      $Destination.Dispose()
      $Source.Dispose()
    }
  }
}

Describe 'Test-ExtractionPattern' {
  It 'matches archive paths across slash conventions' {
    Test-ExtractionPattern -Path 'bin/updater.exe' -Pattern 'bin\updater.exe' | Should -BeTrue
    Test-ExtractionPattern -Path 'bin\updater.exe' -Pattern 'bin/updater.exe' | Should -BeTrue
  }
}

Describe 'Resolve-UniqueInstallerFile' {
  It 'prefers one exact relative path over wildcard interpretation' {
    $Root = Join-Path $TestDrive 'UniqueSelection'
    $null = New-Item -Path (Join-Path $Root 'x64') -ItemType Directory -Force
    $null = New-Item -Path (Join-Path $Root 'arm64') -ItemType Directory -Force
    [IO.File]::WriteAllText((Join-Path $Root 'x64\package.msi'), 'x64')
    [IO.File]::WriteAllText((Join-Path $Root 'arm64\package.msi'), 'arm64')
    $Files = @(Get-ChildItem -LiteralPath $Root -Recurse -File)

    (Resolve-UniqueInstallerFile -Item $Files -Pattern 'x64\package.msi' -BasePath $Root).FullName |
      Should -Be (Join-Path $Root 'x64\package.msi')
    { Resolve-UniqueInstallerFile -Item $Files -Pattern '*.msi' -BasePath $Root } | Should -Throw '*Multiple files matched*'
  }
}

Describe 'Installer condition evaluation' {
  It 'applies Boolean precedence while preserving unknown identifiers' {
    $Result = Resolve-InstallerBooleanExpression -Expression 'WINDOWS || DYNAMIC && false' -IdentifierState ([ordered]@{
        WINDOWS = 'True'
        DYNAMIC = 'Unknown'
      })

    $Result.State | Should -Be 'True'
    $Result.Identifiers | Should -Be @('DYNAMIC', 'WINDOWS')
    $Result.UnknownIdentifiers | Should -Contain 'DYNAMIC'
    Merge-InstallerConditionState -State @('False', 'Unknown') -Operator All | Should -Be 'False'
    Merge-InstallerConditionState -State @('False', 'Unknown') -Operator Any | Should -Be 'Unknown'
    Merge-InstallerConditionState -State @('False', 'False') -Operator None | Should -Be 'True'
  }

  It 'rejects malformed and over-deep expressions without throwing' {
    (Resolve-InstallerBooleanExpression -Expression 'a + b' -IdentifierState @{}).State | Should -Be 'Unknown'
    (Resolve-InstallerBooleanExpression -Expression ('(' * 40 + 'true' + ')' * 40) -IdentifierState @{} -MaximumDepth 8).State | Should -Be 'Unknown'
  }
}

Describe 'Get-PEVersionStringTable' {
  It 'parses named StringFileInfo values from a PE version resource' {
    $ExecutablePath = (Get-Process -Id $PID).Path
    $VersionStrings = Get-PEVersionStringTable -Path $ExecutablePath

    $VersionStrings.ProductName | Should -Not -BeNullOrEmpty
    $VersionStrings.ProductVersion | Should -Not -BeNullOrEmpty
    $VersionStrings.FileDescription | Should -Not -BeNullOrEmpty
  }

  It 'reads layout through a caller-owned stream and restores its position' {
    $ExecutablePath = (Get-Process -Id $PID).Path
    $Stream = [IO.File]::OpenRead($ExecutablePath)
    $Stream.Position = 5
    try {
      $Layout = Get-PELayout -Stream $Stream
      $Layout.Sections.Count | Should -BeGreaterThan 0
      $Stream.Position | Should -Be 5
    } finally { $Stream.Dispose() }
  }

  It 'reads a PE layout when a large installer overlay exceeds the PEReader size limit' {
    $ExecutableBytes = [IO.File]::ReadAllBytes((Get-Process -Id $PID).Path)
    $PeOffset = [BitConverter]::ToInt32($ExecutableBytes, 0x3C)
    $OptionalHeaderOffset = $PeOffset + 24
    $DataDirectoryOffset = $OptionalHeaderOffset + $(if ([BitConverter]::ToUInt16($ExecutableBytes, $OptionalHeaderOffset) -eq 0x20B) { 112 } else { 96 })
    $CertificateEntryOffset = $DataDirectoryOffset + (4 * 8)
    $LargeCertificateOffset = [uint32]([long][int]::MaxValue + 1024)
    [BitConverter]::GetBytes($LargeCertificateOffset).CopyTo($ExecutableBytes, $CertificateEntryOffset)
    [BitConverter]::GetBytes([uint32]512).CopyTo($ExecutableBytes, $CertificateEntryOffset + 4)

    $VirtualLength = [long]$LargeCertificateOffset + 512
    $Stream = [Dumplings.Tests.VirtualLargeReadStream]::new($ExecutableBytes, $VirtualLength)
    $Stream.Position = 11
    try {
      [Dumplings.InstallerInfrastructure.PEImageReader]::GetReaderSize($Stream) | Should -Be ([int]::MaxValue)
      $Layout = Get-PELayout -Stream $Stream
      $Layout.Sections.Count | Should -BeGreaterThan 0
      $Layout.DataDirectories.Certificate.Offset | Should -Be $LargeCertificateOffset
      $Stream.Position | Should -Be 11
    } finally { $Stream.Dispose() }
  }

  It 'reuses a caller-provided PE layout while enumerating resources' {
    $ExecutablePath = (Get-Process -Id $PID).Path
    $Stream = [IO.File]::OpenRead($ExecutablePath)
    $Stream.Position = 7
    try {
      $Layout = Get-PELayout -Stream $Stream
      $Resources = @(Get-PEResourceInfo -Stream $Stream -Layout $Layout)

      $Resources.Count | Should -BeGreaterThan 0
      $Stream.Position | Should -Be 7
      [object]::ReferenceEquals($Resources[0].SourceStream, $Stream) | Should -BeTrue
    } finally { $Stream.Dispose() }
  }
}

Describe 'Shared archive helpers' {
  It 'resolves relative paths against the PowerShell filesystem location' {
    $PowerShellRoot = Join-Path $TestDrive 'PowerShellLocation'
    $null = New-Item -Path $PowerShellRoot -ItemType Directory
    $SourcePath = Join-Path $PowerShellRoot 'source.bin'
    [IO.File]::WriteAllBytes($SourcePath, [byte[]](1, 2, 3))
    $OriginalDotNetDirectory = [Environment]::CurrentDirectory
    Push-Location $PowerShellRoot
    try {
      [Environment]::CurrentDirectory = $Script:TemporaryRoot
      Resolve-InstallerFileSystemPath -Path '.\source.bin' -PathType Leaf | Should -Be $SourcePath
      Resolve-InstallerFileSystemPath -Path '.\output' -AllowNonexistent | Should -Be (Join-Path $PowerShellRoot 'output')
    } finally {
      [Environment]::CurrentDirectory = $OriginalDotNetDirectory
      Pop-Location
    }
  }

  It 'applies deterministic extraction collision policies' {
    $OutputRoot = Join-Path $TestDrive 'Collisions'
    $null = New-Item -Path $OutputRoot -ItemType Directory
    $ExistingPath = Join-Path $OutputRoot 'payload.txt'
    [IO.File]::WriteAllText($ExistingPath, 'existing')

    { Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Error } |
      Should -Throw '*already exists*'
    (Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Skip).ShouldWrite |
      Should -BeFalse
    (Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Overwrite).Path |
      Should -Be $ExistingPath
    $Renamed = Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Rename
    $Renamed.Path | Should -Be (Join-Path $OutputRoot 'payload (1).txt')
    $Renamed.Disposition | Should -Be 'Rename'

    $Reserved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $Reserved.Add((Join-Path $OutputRoot 'new.bin'))
    (Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'new.bin' -CollisionAction Rename -ReservedPath $Reserved).Path |
      Should -Be (Join-Path $OutputRoot 'new (1).bin')
  }

  It 'prompts only when the Prompt policy encounters a collision' {
    $OutputRoot = Join-Path $TestDrive 'PromptCollision'
    $null = New-Item -Path $OutputRoot -ItemType Directory
    [IO.File]::WriteAllText((Join-Path $OutputRoot 'payload.txt'), 'existing')
    Mock Read-InstallerCollisionAction -ModuleName Binary { 'Skip' }

    $Collision = Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'payload.txt' -CollisionAction Prompt
    $Collision.ShouldWrite | Should -BeFalse
    $Available = Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath 'available.txt' -CollisionAction Prompt
    $Available.ShouldWrite | Should -BeTrue

    Should -Invoke Read-InstallerCollisionAction -ModuleName Binary -Times 1 -Exactly -ParameterFilter {
      $CollisionAction -eq 'Prompt' -and $Path -eq (Join-Path $OutputRoot 'payload.txt')
    }
  }

  It 'decodes a bounded four-stream BCJ2 payload through SharpCompress' {
    $Expected = [byte[]](1, 2, 3, 4, 5, 6)
    $Streams = [System.IO.Stream[]]@(
      [IO.MemoryStream]::new($Expected, $false),
      [IO.MemoryStream]::new([byte[]]::new(0), $false),
      [IO.MemoryStream]::new([byte[]]::new(0), $false),
      [IO.MemoryStream]::new([byte[]](0, 0, 0, 0, 0), $false)
    )
    $Decoder = New-InstallerBcj2DecoderStream -Stream $Streams -UncompressedSize $Expected.Length
    try {
      $Actual = [byte[]]::new($Expected.Length)
      $Decoder.Read($Actual, 0, $Actual.Length) | Should -Be $Expected.Length
      $Actual | Should -Be $Expected
    } finally {
      $Decoder.Dispose()
      foreach ($Stream in $Streams) { $Stream.Dispose() }
    }
  }

  It 'opens and exports a bounded ZIP entry' {
    $ZipPath = Join-Path $Script:TemporaryRoot 'sample.zip'
    $SourcePath = Join-Path $Script:TemporaryRoot 'source.txt'
    [IO.File]::WriteAllText($SourcePath, 'shared archive')
    Compress-Archive -LiteralPath $SourcePath -DestinationPath $ZipPath -Force
    $Archive = Get-InstallerArchive -Path $ZipPath
    try {
      $Entry = @(Get-InstallerArchiveEntry -Archive $Archive)[0]
      $OutputPath = Resolve-SafeExtractionPath -DestinationPath (Join-Path $Script:TemporaryRoot 'out') -RelativePath $Entry.FullName
      $Result = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024
      $Result | Should -Exist
      [IO.File]::ReadAllText($Result.FullName) | Should -Be 'shared archive'

      $Renamed = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Rename
      $Renamed.Name | Should -Be 'source (1).txt'
      (Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Skip) |
        Should -BeNullOrEmpty
      { Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Error } |
        Should -Throw '*already exists*'
      (Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes 1024 -CollisionAction Overwrite).FullName |
        Should -Be $OutputPath
    } finally {
      $Archive.Dispose()
    }
  }

  It 'opens an embedded archive range without materializing it' {
    $ZipPath = Join-Path $Script:TemporaryRoot 'range-source.zip'
    $SourcePath = Join-Path $Script:TemporaryRoot 'range-source.txt'
    $EmbeddedPath = Join-Path $Script:TemporaryRoot 'embedded-range.bin'
    [IO.File]::WriteAllText($SourcePath, 'bounded range archive')
    Compress-Archive -LiteralPath $SourcePath -DestinationPath $ZipPath -Force
    $Prefix = [byte[]]::new(257)
    $ZipBytes = [IO.File]::ReadAllBytes($ZipPath)
    [IO.File]::WriteAllBytes($EmbeddedPath, $Prefix + $ZipBytes + [byte[]]::new(31))

    $Context = Open-InstallerArchiveRange -Path $EmbeddedPath -Offset $Prefix.Length -Length $ZipBytes.Length
    try {
      $Entry = @(Get-InstallerArchiveEntry -Archive $Context.Archive)[0]
      Read-InstallerArchiveEntryText -Entry $Entry -MaximumBytes 1024 | Should -Be 'bounded range archive'
    } finally {
      Close-InstallerArchiveRange -Context $Context
    }

    { Remove-Item -LiteralPath $EmbeddedPath -Force } | Should -Not -Throw
  }

  It 'rejects traversal and output-limit violations' {
    { Resolve-SafeExtractionPath -DestinationPath $Script:TemporaryRoot -RelativePath '..\escape.bin' } | Should -Throw
  }

  It 'derives and validates exact embedded 7z archive ranges without external tools' {
    $ArchiveBytes = [Convert]::FromBase64String('N3q8ryccAAQs8sR6JAAAAAAAAABiAAAAAAAAANg7gnEBAB/vu79EdW1wbGluZ3MgZW1iZWRkZWQgN3ogZml4dHVyZQABBAYAAQkkAAcLAQABISEBAAwgAAgKASE86hYAAAUBGQwAAAAAAAAAAAAAAAARGQBmAGkAeAB0AHUAcgBlAC4AdAB4AHQAAAAZAgAAFAoBABhQp0tLEN0BFQYBACAAAAAAAA==')
    $Prefix = [byte[]]::new(4096)
    $Suffix = [Text.Encoding]::ASCII.GetBytes('trailing-data-that-is-not-part-of-the-archive')
    $Path = Join-Path $Script:TemporaryRoot 'embedded-7z.bin'
    [IO.File]::WriteAllBytes($Path, $Prefix + $ArchiveBytes + $Suffix)

    $Ranges = @(Get-EmbeddedSevenZipArchiveRange -Path $Path -StartOffset 1024)

    $Ranges | Should -HaveCount 1
    $Ranges[0].Offset | Should -Be 4096
    $Ranges[0].Length | Should -Be $ArchiveBytes.Length
    $Ranges[0].EntryCount | Should -Be 1
  }
}
