. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\..\PackageModule.psd1') -Force -Global
}

Describe 'Reusable parser readers' -Tag Unit {
  It 'preserves first-present dictionary values without truthiness fallback' {
    Get-DictionaryValue -Dictionary @{ First = ''; Second = 'fallback' } -Name First, Second | Should -BeExactly ''
    Get-DictionaryValue -Dictionary @{ First = $false; Second = $true } -Name First, Second | Should -BeFalse
    Get-DictionaryValue -Dictionary @{ First = $null; Second = 'fallback' } -Name First, Second | Should -BeNullOrEmpty
    Get-DictionaryValue -Dictionary @{ Second = 'fallback' } -Name First, Second | Should -BeExactly 'fallback'
  }

  It 'reads either byte order without modifying the caller buffer' {
    $Bytes = [byte[]](0xAA, 0x12, 0x34, 0xBB)
    Read-BinaryInteger -Bytes $Bytes -Offset 1 -Size 2 -Endian BigEndian | Should -Be 0x1234
    Read-BinaryInteger -Bytes $Bytes -Offset 1 -Size 2 | Should -Be 0x3412
    $Bytes | Should -Be ([byte[]](0xAA, 0x12, 0x34, 0xBB))
    $SignedByte = Read-BinaryInteger -Bytes ([byte[]](255)) -Offset 0 -Size 1 -Signed
    $SignedByte | Should -Be -1
    $SignedByte | Should -BeOfType ([sbyte])
    { Read-BinaryInteger -Bytes $Bytes -Offset ([long]::MaxValue) -Size 8 } | Should -Throw '*outside*'
    { Read-BinaryInteger -Bytes $Bytes -Offset -1 -Size 1 } | Should -Throw '*outside*'
    { Read-BinaryInteger -Bytes @() -Offset 0 -Size 1 } | Should -Throw '*outside*'
  }

  It 'restores a stream after an integer read' {
    $Stream = [IO.MemoryStream]::new([byte[]](0, 0xFF, 0xFF, 0))
    try {
      $Stream.Position = 3
      Read-BinaryInteger -Stream $Stream -Offset 1 -Size 2 -Signed | Should -Be -1
      Read-BinaryInteger $Stream 1 2 'LittleEndian' -Signed | Should -Be -1
      $Stream.Position | Should -Be 3
    } finally { $Stream.Dispose() }
  }

  It 'preserves integer width and signedness at each boundary' {
    foreach ($Width in 1, 2, 4, 8) {
      foreach ($Endian in 'LittleEndian', 'BigEndian') {
        $Bytes = [byte[]]::new($Width)
        [Array]::Fill[byte]($Bytes, 255)
        $Signed = Read-BinaryInteger -Bytes $Bytes -Offset 0 -Size $Width -Endian $Endian -Signed
        $Signed | Should -Be -1
        $Signed | Should -BeOfType (@{ 1 = [sbyte]; 2 = [int16]; 4 = [int32]; 8 = [int64] }[$Width])
        $Unsigned = Read-BinaryInteger -Bytes $Bytes -Offset 0 -Size $Width -Endian $Endian
        $Unsigned | Should -BeOfType (@{ 1 = [byte]; 2 = [uint16]; 4 = [uint32]; 8 = [uint64] }[$Width])
        $Unsigned | Should -Be (@{ 1 = [byte]::MaxValue; 2 = [uint16]::MaxValue; 4 = [uint32]::MaxValue; 8 = [uint64]::MaxValue }[$Width])
      }
    }
  }

  It 'advances sequential reads and rejects truncated integers without closing the stream' {
    $Stream = [IO.MemoryStream]::new([byte[]](0x12, 0x34, 0xFF))
    try {
      Read-BinarySequentialInteger -Stream $Stream -Size 2 -Endian BigEndian | Should -Be 0x1234
      $Stream.Position | Should -Be 2
      { Read-BinarySequentialInteger -Stream $Stream -Size 2 } | Should -Throw '*end of stream*'
      $Stream.Position | Should -Be 3
      $Stream.CanRead | Should -BeTrue
    } finally { $Stream.Dispose() }
  }

  It 'decodes bounded text and restores the original position' {
    $Stream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('prefix:payload'))
    try {
      $Stream.Position = 7
      Read-BoundedTextStream -Stream $Stream -MaximumBytes 7 | Should -BeExactly 'payload'
      $Stream.Position | Should -Be 7
      { Read-BoundedTextStream -Stream $Stream -MaximumBytes 6 } | Should -Throw '*limit*'
      $Stream.Position | Should -Be 7
      $Stream.CanRead | Should -BeTrue
    } finally { $Stream.Dispose() }
  }

  It 'supports standalone text decoding without globally exporting infrastructure commands' {
    $ScriptPath = Join-Path $TestDrive 'StandaloneText.ps1'
    @'
param([string]$ModulePath)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath
$Stream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('standalone'))
try {
  Read-BoundedTextStream -Stream $Stream -MaximumBytes 20
  if ($Stream.Position -ne 0 -or -not $Stream.CanRead) { throw 'Caller stream ownership changed' }
  if (Get-Command New-BoundedReadStream -ErrorAction Ignore) { throw 'Private dependency leaked globally' }
} finally { $Stream.Dispose() }
'@ | Set-Content -LiteralPath $ScriptPath -Encoding utf8NoBOM
    $Output = & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $ScriptPath -ModulePath (Join-Path $PSScriptRoot '..\..\Libraries\Data\Text.psm1')
    $LASTEXITCODE | Should -Be 0
    $Output | Should -BeExactly 'standalone'
  }

  It 'honors BOMs and explicit legacy fallback' {
    foreach ($Encoding in [Text.Encoding]::Unicode, [Text.Encoding]::BigEndianUnicode, [Text.Encoding]::UTF8) {
      $Stream = [IO.MemoryStream]::new([byte[]]($Encoding.GetPreamble() + $Encoding.GetBytes('text')))
      try { Read-BoundedTextStream -Stream $Stream -MaximumBytes 100 | Should -BeExactly 'text' } finally { $Stream.Dispose() }
    }
    $Stream = [IO.MemoryStream]::new([byte[]](0x80))
    try { Read-BoundedTextStream -Stream $Stream -MaximumBytes 1 -FallbackEncoding windows-1252 | Should -BeExactly ([string][char]0x20AC) } finally { $Stream.Dispose() }
  }

  It 'infers BOM-less Unicode relative to the text range' {
    $Stream = [IO.MemoryStream]::new([byte[]]([Text.Encoding]::ASCII.GetBytes('binary-header') + [Text.Encoding]::Unicode.GetBytes('decoded text')))
    try {
      $Stream.Position = 13
      Read-BoundedTextStream -Stream $Stream -MaximumBytes 24 -DetectBomlessUnicode | Should -BeExactly 'decoded text'
      $Stream.Position | Should -Be 13
      $Stream.CanRead | Should -BeTrue
    } finally { $Stream.Dispose() }
  }

  It 'keeps malformed inferred Unicode terminal unless the format permits fallback' {
    $Stream = [IO.MemoryStream]::new([byte[]](65, 0, 66, 0, 67))
    try {
      { Read-BoundedTextStream -Stream $Stream -MaximumBytes 5 -DetectBomlessUnicode } | Should -Throw
      $Stream.Position | Should -Be 0
      Read-BoundedTextStream -Stream $Stream -MaximumBytes 5 -DetectBomlessUnicode -AllowUnicodeFallback -FallbackEncoding windows-1252 | Should -BeExactly "A`0B`0C"
      $Stream.Position | Should -Be 0
    } finally { $Stream.Dispose() }
  }

  It 'preserves XML content and rejects external declarations and oversized input' {
    $Xml = Read-BoundedXmlDocument -Content '<root value=" a ">text</root>' -MaximumCharacters 100
    $Xml.DocumentElement.GetAttribute('value') | Should -BeExactly ' a '
    $Xml.DocumentElement.InnerText | Should -BeExactly 'text'
    { Read-BoundedXmlDocument -Content '<root>too long</root>' -MaximumCharacters 10 } | Should -Throw
    { Read-BoundedXmlDocument -Content '<!DOCTYPE root [<!ENTITY x SYSTEM "file:///never-read">]><root>&x;</root>' -MaximumCharacters 200 } | Should -Throw
    { Read-BoundedXmlDocument -Content '<root>' -MaximumCharacters 100 } | Should -Throw
  }

  It 'loads a provider from a literal path once' {
    $Path = Join-Path $PSScriptRoot '..\..\Assets\Providers\SharpCompress.Gentee\SharpCompress.Gentee.dll'
    $First = Import-InstallerManagedAssembly -Path $Path -TypeName 'SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder'
    $Second = Import-InstallerManagedAssembly -Path $Path -TypeName 'SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder'
    [object]::ReferenceEquals($First, $Second) | Should -BeTrue
    (Import-InstallerManagedAssembly 'ZstdSharp.dll' 'ZstdSharp.Decompressor').GetName().Name | Should -BeExactly 'ZstdSharp'
  }

  It 'keeps public parser ownership and private implementation commands separate' {
    foreach ($Family in 'CreateInstall', 'DeployMaster', 'InstallBuilder') {
      (Get-Command "${Family}\Get-${Family}Info").ModuleName | Should -Be $Family
      Get-Help "Get-${Family}Info" -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }
    Get-Command Read-CreateInstallGenteeBwd -ErrorAction Ignore | Should -BeNullOrEmpty
    Get-Command Read-DeployMasterClassicPackageData -ErrorAction Ignore | Should -BeNullOrEmpty
    Get-Command Get-InstallBuilderCookfsInfo -ErrorAction Ignore | Should -BeNullOrEmpty
  }
}
