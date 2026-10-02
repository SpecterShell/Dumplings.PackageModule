. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  . (Join-Path $PSScriptRoot '..\..\Index.ps1')
  . (Join-Path $PSScriptRoot '..\Support\TestFixture.ps1')
  & (Get-Module TigerSetup) { Import-TigerSetupReader }

  function ConvertTo-TestTigerVarint([uint64]$Value) {
    $Bytes = [Collections.Generic.List[byte]]::new()
    do {
      $Byte = [byte]($Value -band 127)
      $Value = $Value -shr 7
      if ($Value) { $Byte = $Byte -bor 128 }
      $Bytes.Add($Byte)
    } while ($Value)
    return , $Bytes.ToArray()
  }
  function New-TestTigerField([int]$Number, [object]$Value, [int]$Wire = 2) {
    $Output = [IO.MemoryStream]::new()
    try {
      $Output.Write((ConvertTo-TestTigerVarint (($Number -shl 3) -bor $Wire)))
      switch ($Wire) {
        0 { $Output.Write((ConvertTo-TestTigerVarint $Value)) }
        2 {
          $Bytes = $Value -is [byte[]] ? $Value : [Text.Encoding]::UTF8.GetBytes([string]$Value)
          $Output.Write((ConvertTo-TestTigerVarint $Bytes.Length))
          $Output.Write($Bytes)
        }
        5 { $Output.Write([BitConverter]::GetBytes([uint32]$Value)) }
      }
      return , $Output.ToArray()
    } finally { $Output.Dispose() }
  }
  function Join-TestTigerFields([byte[][]]$Fields) {
    $Output = [IO.MemoryStream]::new()
    try { foreach ($Field in $Fields) { $Output.Write($Field) }; return , $Output.ToArray() } finally { $Output.Dispose() }
  }
  function New-TestTigerFixture {
    param ([string]$Path, [int[]]$Scopes = @(1, 2), [string]$FilePath = 'bin/app.txt', [switch]$BadEntryCrc, [switch]$BadHash, [switch]$Signed, [byte[]]$ExtraMetadata = @(), [ValidateSet(1, 2, 3)][int]$FormatMajor = 3, [string]$BuilderVersion = '', [int]$SchemaVersion = 0, [ValidateSet('Optimal', 'NoCompression')][string]$ZipCompression = 'Optimal', [byte[]]$PayloadData)
    # Minimal PE32+ image; it is data only and cannot execute as a program.
    $Loader = [byte[]]::new(1024)
    [BitConverter]::GetBytes([uint16]0x5A4D).CopyTo($Loader, 0)
    [BitConverter]::GetBytes(128).CopyTo($Loader, 60)
    [BitConverter]::GetBytes(0x4550).CopyTo($Loader, 128)
    [BitConverter]::GetBytes([uint16]0x8664).CopyTo($Loader, 132)
    [BitConverter]::GetBytes([uint16]1).CopyTo($Loader, 134)
    [BitConverter]::GetBytes([uint16]240).CopyTo($Loader, 148)
    [BitConverter]::GetBytes([uint16]0x20B).CopyTo($Loader, 152)
    [BitConverter]::GetBytes(512).CopyTo($Loader, 212)
    [BitConverter]::GetBytes([uint16]2).CopyTo($Loader, 220)
    [BitConverter]::GetBytes(16).CopyTo($Loader, 260)
    [Text.Encoding]::ASCII.GetBytes('.text').CopyTo($Loader, 392)
    [BitConverter]::GetBytes(512).CopyTo($Loader, 408)
    [BitConverter]::GetBytes(512).CopyTo($Loader, 412)
    $EngineRaw = [Text.Encoding]::ASCII.GetBytes('not executable')
    $Engine = [Dumplings.TigerSetup.MetadataReader]::StoredZstd($EngineRaw)
    $Data = $PSBoundParameters.ContainsKey('PayloadData') ? $PayloadData : [Text.Encoding]::UTF8.GetBytes('Tiger payload')
    $Payload = [Dumplings.TigerSetup.MetadataReader]::StoredZstd($Data)
    if ($Data.Length -eq 0) { $Payload = [byte[]]::new(0) }
    if ($FormatMajor -eq 1) {
      $ZipBytes = [IO.MemoryStream]::new()
      $Zip = [IO.Compression.ZipArchive]::new($ZipBytes, [IO.Compression.ZipArchiveMode]::Create, $true)
      try {
        $ZipEntry = $Zip.CreateEntry('file', [IO.Compression.CompressionLevel]::$ZipCompression)
        $EntryStream = $ZipEntry.Open()
        try { $EntryStream.Write($Data) } finally { $EntryStream.Dispose() }
      } finally { $Zip.Dispose() }
      try { $Payload = $ZipBytes.ToArray() } finally { $ZipBytes.Dispose() }
    }
    $Hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Data)).ToLowerInvariant()
    $Package = Join-TestTigerFields @((New-TestTigerField 1 'Vendor.Tiger'), (New-TestTigerField 2 'Tiger Test'), (New-TestTigerField 3 '1.2.3'), (New-TestTigerField 4 'Publisher'))
    $ScopeBytes = Join-TestTigerFields @($Scopes | ForEach-Object { ConvertTo-TestTigerVarint $_ })
    $Install = Join-TestTigerFields @((New-TestTigerField 1 $ScopeBytes), (New-TestTigerField 2 '%LOCALAPPDATA%\Programs\Tiger Test'), (New-TestTigerField 3 '%PROGRAMFILES%\Tiger Test'), (New-TestTigerField 5 'x64'), (New-TestTigerField 6 $Data.Length 0))
    $File = Join-TestTigerFields @((New-TestTigerField 1 $FilePath), (New-TestTigerField 2 $Data.Length 0), (New-TestTigerField 3 'file'))
    $Crc = $Data.Length ? (Get-BinaryCrc32 -Bytes $Data) : 0u
    $Entry = Join-TestTigerFields @((New-TestTigerField 1 'file'), (New-TestTigerField 3 $Data.Length 0), (New-TestTigerField 4 ($BadEntryCrc ? 123 : $Crc) 5), (New-TestTigerField 5 ($BadHash ? ('0' * 64) : $Hash)))
    $Batch = Join-TestTigerFields @((New-TestTigerField 2 1 0), (New-TestTigerField 3 $Data.Length 0))
    $Reg = Join-TestTigerFields @((New-TestTigerField 1 'Custom.Tiger'), (New-TestTigerField 2 'ARP Tiger'), (New-TestTigerField 3 '4.5.6'), (New-TestTigerField 4 $FilePath))
    $Option = Join-TestTigerFields @((New-TestTigerField 1 'links'), (New-TestTigerField 2 1 0), (New-TestTigerField 3 3 0))
    $When = Join-TestTigerFields @((New-TestTigerField 1 'links'), (New-TestTigerField 2 'true'))
    $Protocol = Join-TestTigerFields @((New-TestTigerField 1 'tiger'), (New-TestTigerField 5 $FilePath), (New-TestTigerField 7 $When))
    $Association = Join-TestTigerFields @((New-TestTigerField 1 'Tiger.File'), (New-TestTigerField 2 '.tiger'), (New-TestTigerField 5 $FilePath), (New-TestTigerField 7 $When))
    if (-not $BuilderVersion) { $BuilderVersion = @('', '0.5.2', '0.8.0', '0.14.0')[$FormatMajor] }
    if (-not $SchemaVersion) { $SchemaVersion = $FormatMajor -eq 3 ? 2 : 1 }
    $Fields = [Collections.Generic.List[byte[]]]::new()
    foreach ($Field in @((New-TestTigerField 1 $SchemaVersion 0), (New-TestTigerField 2 $Package), (New-TestTigerField 3 $Install), (New-TestTigerField 4 $File), (New-TestTigerField 6 (New-TestTigerField 1 $BuilderVersion)), (New-TestTigerField 7 1 0), (New-TestTigerField 9 $Option), (New-TestTigerField 13 $Reg))) { $Fields.Add($Field) }
    for ($Separator = $FilePath.IndexOf('/'); $Separator -ge 0; $Separator = $FilePath.IndexOf('/', $Separator + 1)) {
      $Fields.Add((New-TestTigerField 5 (New-TestTigerField 1 $FilePath.Substring(0, $Separator))))
    }
    if ([version]$BuilderVersion -ge [version]'0.6.0') { $Fields.Add((New-TestTigerField 17 $Association)); $Fields.Add((New-TestTigerField 18 $Protocol)) }
    if ($FormatMajor -gt 1) { $Fields.Add((New-TestTigerField 23 $Entry)) }
    if ($FormatMajor -eq 3) { $Fields.Add((New-TestTigerField 25 $Batch)) }
    $Fields.Add($ExtraMetadata)
    $Metadata = Join-TestTigerFields $Fields.ToArray()
    $Compressed = $FormatMajor -eq 3 ? [Dumplings.TigerSetup.MetadataReader]::StoredZstd($Metadata) : $Metadata
    $FooterLength = @(0, 128, 256, 320)[$FormatMajor]
    $EngineLength = $FormatMajor -eq 1 ? 0 : $Engine.Length
    if ($Signed) {
      $Padding = (8 - (($Loader.Length + $EngineLength + $Payload.Length + $Compressed.Length + $FooterLength) % 8)) % 8
      [Array]::Resize([ref]$Loader, $Loader.Length + $Padding)
      [BitConverter]::GetBytes($Loader.Length + $EngineLength + $Payload.Length + $Compressed.Length + $FooterLength).CopyTo($Loader, 296)
      [BitConverter]::GetBytes(8).CopyTo($Loader, 300)
    }
    $Footer = [byte[]]::new($FooterLength)
    [Text.Encoding]::ASCII.GetBytes('TIGERSTP').CopyTo($Footer, 0)
    [BitConverter]::GetBytes([uint16]$FormatMajor).CopyTo($Footer, 8)
    [BitConverter]::GetBytes($FooterLength).CopyTo($Footer, 12)
    $Offset = [long]$Loader.Length
    # Independent framing oracle: copy the three upstream footer layouts, not
    # the production catalog. Historical images are non-executable synthetic data.
    $Blocks = switch ($FormatMajor) {
      1 { , @(@(16, $Compressed, -1, 48), @(32, $Payload, -1, 80)) }
      2 { , @(@(16, $Engine, $EngineRaw.Length, 80), @(56, $Payload, $Data.Length, 176), @(40, $Compressed, -1, 144)) }
      3 { , @(@(16, $Engine, $EngineRaw.Length, 88), @(40, $Payload, $Data.Length, 152), @(64, $Compressed, $Metadata.Length, 184)) }
    }
    foreach ($Block in $Blocks) {
      [BitConverter]::GetBytes([uint64]$Offset).CopyTo($Footer, $Block[0])
      [BitConverter]::GetBytes([uint64]$Block[1].Length).CopyTo($Footer, $Block[0] + 8)
      if ($Block[2] -ge 0) { [BitConverter]::GetBytes([uint64]$Block[2]).CopyTo($Footer, $Block[0] + 16) }
      [Security.Cryptography.SHA256]::HashData($Block[1]).CopyTo($Footer, $Block[3])
      $Offset += $Block[1].Length
    }
    if ($FormatMajor -gt 1) { [Security.Cryptography.SHA256]::HashData($EngineRaw).CopyTo($Footer, ($FormatMajor -eq 2 ? 112 : 120)) }
    if ($FormatMajor -eq 3) { [Security.Cryptography.SHA256]::HashData($Metadata).CopyTo($Footer, 216) }
    [Text.Encoding]::ASCII.GetBytes('PTSREGIT').CopyTo($Footer, $FooterLength - 8)
    [BitConverter]::GetBytes((Get-BinaryCrc32 -Bytes $Footer -Count ($FooterLength - 12))).CopyTo($Footer, $FooterLength - 12)
    $Output = [IO.File]::Create($Path)
    try { $Output.Write($Loader); foreach ($Block in $Blocks) { $Output.Write($Block[1]) }; $Output.Write($Footer); if ($Signed) { $Output.Write([byte[]](8, 0, 0, 0, 0, 2, 2, 0)) } } finally { $Output.Dispose() }
    return $Path
  }
  $Script:Fixture = New-TestTigerFixture -Path (Join-Path $TestDrive 'setup.exe')
}

Describe 'TigerSetup static metadata and extraction' {
  It 'Merges singular messages without losing earlier scalars or explicit optional presence' {
    $First = New-TestTigerField 2 (Join-TestTigerFields @((New-TestTigerField 1 'Vendor.Tiger'), (New-TestTigerField 2 'Before')))
    $Second = New-TestTigerField 2 (Join-TestTigerFields @((New-TestTigerField 2 ''), (New-TestTigerField 3 '1.2.3')))
    $Result = [Dumplings.TigerSetup.MetadataReader]::Read((Join-TestTigerFields @($First, $Second)))
    $Result.package.id | Should -Be Vendor.Tiger
    $Result.package.name | Should -BeExactly ''
    $Result.package.version | Should -Be '1.2.3'
    $Absent = [Dumplings.TigerSetup.MetadataReader]::Read((New-TestTigerField 26 (New-TestTigerField 1 'app.exe')))
    $Explicit = [Dumplings.TigerSetup.MetadataReader]::Read((New-TestTigerField 26 (New-TestTigerField 3 '')))
    $Absent.launch.PresentFields.Contains('working_directory') | Should -BeFalse
    $Explicit.launch.PresentFields.Contains('working_directory') | Should -BeTrue
  }
  It 'Decodes declared numeric widths and signed packed return codes like Protobuf' {
    $Codes = ConvertTo-TestTigerVarint ([uint64]::MaxValue)
    $Action = Join-TestTigerFields @((New-TestTigerField 12 4294967297 0), (New-TestTigerField 13 $Codes))
    $Result = [Dumplings.TigerSetup.MetadataReader]::Read((New-TestTigerField 22 $Action))
    $Result.actions[0].timeout_seconds | Should -Be 1
    $Result.actions[0].success_codes[0] | Should -Be -1
    $Result.actions[0].success_codes[0] | Should -BeOfType ([int])
  }
  It 'Rejects malformed <Case> before projecting ARP' -ForEach @(
    @{ Case = 'identity'; Fields = { New-TestTigerField 2 (New-TestTigerField 1 'Bad.') } },
    @{ Case = 'version'; Fields = { New-TestTigerField 2 (New-TestTigerField 3 '01.2.3') } },
    @{ Case = 'directory'; Fields = { New-TestTigerField 5 (New-TestTigerField 1 '../escape') } },
    @{ Case = 'reserved file'; Fields = { New-TestTigerField 4 (Join-TestTigerFields @((New-TestTigerField 1 '.tigersetup/actions/bad.exe'), (New-TestTigerField 3 'file'))) } },
    @{ Case = 'predicate'; Fields = { New-TestTigerField 11 (New-TestTigerField 3 (Join-TestTigerFields @((New-TestTigerField 1 'absent'), (New-TestTigerField 2 'true')))) } },
    @{ Case = 'option kind'; Fields = { New-TestTigerField 9 (Join-TestTigerFields @((New-TestTigerField 1 'bad'), (New-TestTigerField 3 99 0))) } },
    @{ Case = 'unlabeled option'; Fields = { New-TestTigerField 9 (New-TestTigerField 1 'bad') } },
    @{ Case = 'scope policy'; Fields = { New-TestTigerField 3 (New-TestTigerField 7 99 0) } },
    @{ Case = 'shortcut'; Fields = { New-TestTigerField 10 (Join-TestTigerFields @((New-TestTigerField 1 1 0), (New-TestTigerField 2 'CON'), (New-TestTigerField 3 'bin/app.txt'))) } },
    @{ Case = 'environment'; Fields = { New-TestTigerField 16 (New-TestTigerField 1 'Path') } },
    @{ Case = 'protocol'; Fields = { New-TestTigerField 18 (Join-TestTigerFields @((New-TestTigerField 1 'https'), (New-TestTigerField 5 'bin/app.txt'))) } },
    @{ Case = 'association'; Fields = { New-TestTigerField 17 (Join-TestTigerFields @((New-TestTigerField 1 'Bad ProgID'), (New-TestTigerField 2 '.bad'), (New-TestTigerField 5 'bin/app.txt'))) } },
    @{ Case = 'App Paths'; Fields = { New-TestTigerField 19 (New-TestTigerField 1 'bin/app.txt') } },
    @{ Case = 'context verb'; Fields = { New-TestTigerField 20 (New-TestTigerField 2 'bad') } },
    @{ Case = 'firewall'; Fields = { New-TestTigerField 21 (Join-TestTigerFields @((New-TestTigerField 1 'bad'), (New-TestTigerField 3 'bin/app.txt'), (New-TestTigerField 4 1 0), (New-TestTigerField 5 1 0), (New-TestTigerField 6 1 0), (New-TestTigerField 7 '90-80'))) } },
    @{ Case = 'registry root'; Fields = { New-TestTigerField 12 (Join-TestTigerFields @((New-TestTigerField 1 'Software\Test'), (New-TestTigerField 3 1 0), (New-TestTigerField 6 1 0))) } },
    @{ Case = 'registry key'; Fields = { New-TestTigerField 12 (Join-TestTigerFields @((New-TestTigerField 1 '\Test'), (New-TestTigerField 3 1 0))) } },
    @{ Case = 'DWORD'; Fields = { New-TestTigerField 12 (Join-TestTigerFields @((New-TestTigerField 1 'Test'), (New-TestTigerField 3 3 0), (New-TestTigerField 4 '4294967296'))) } },
    @{ Case = 'registration'; Fields = { New-TestTigerField 13 (New-TestTigerField 1 'Bad\Key') } },
    @{ Case = 'legacy'; Fields = { New-TestTigerField 14 (Join-TestTigerFields @((New-TestTigerField 1 'msi'), (New-TestTigerField 2 'Old'))) } },
    @{ Case = 'dependency'; Fields = { New-TestTigerField 15 (New-TestTigerField 1 'bad') } },
    @{ Case = 'action'; Fields = { New-TestTigerField 22 (New-TestTigerField 1 'bad') } },
    @{ Case = 'quiescence'; Fields = { New-TestTigerField 24 (New-TestTigerField 1 'bad') } },
    @{ Case = 'completion launch'; Fields = { New-TestTigerField 26 (New-TestTigerField 1 'bin/missing.exe') } }
  ) {
    $Path = New-TestTigerFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.exe')) -ExtraMetadata (& $Fields)
    { Get-TigerSetupInfo $Path } | Should -Throw '*Invalid TigerSetup metadata*'
    Test-TigerSetupInstaller $Path | Should -BeFalse
  }
  It 'Separates case-insensitive option names from literal canonical predicate text' {
    $When = Join-TestTigerFields @((New-TestTigerField 1 'LINKS'), (New-TestTigerField 2 'true'))
    $ExtraProtocol = Join-TestTigerFields @((New-TestTigerField 1 'other-tiger'), (New-TestTigerField 5 'bin/app.txt'), (New-TestTigerField 7 $When))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'alias.exe') -ExtraMetadata (New-TestTigerField 18 $ExtraProtocol)
    (Get-TigerSetupInfo $Path).Protocols | Should -Contain 'other-tiger'
    (Get-TigerSetupInfo $Path -Option @{ links = 'off' }).Protocols.Count | Should -Be 0
    $When = Join-TestTigerFields @((New-TestTigerField 1 'LINKS'), (New-TestTigerField 2 'ON'))
    $ExtraProtocol = Join-TestTigerFields @((New-TestTigerField 1 'noncanonical-tiger'), (New-TestTigerField 5 'bin/app.txt'), (New-TestTigerField 7 $When))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'noncanonical.exe') -ExtraMetadata (New-TestTigerField 18 $ExtraProtocol)
    (Get-TigerSetupInfo $Path -Option @{ links = 'ON' }).Protocols | Should -Not -Contain 'noncanonical-tiger'
  }
  It 'Accepts valid optional-resource contracts without executing their programs' {
    $Detector = Join-TestTigerFields @((New-TestTigerField 1 3 0), (New-TestTigerField 2 '%PROGRAMFILES%\Other\file.dll'))
    $Acquisition = Join-TestTigerFields @((New-TestTigerField 1 2 0), (New-TestTigerField 4 'https://example.test/prerequisite.exe'), (New-TestTigerField 5 ('a' * 64)))
    $Dependency = Join-TestTigerFields @((New-TestTigerField 1 'Other'), (New-TestTigerField 3 '1.2.3.4'), (New-TestTigerField 4 $Detector), (New-TestTigerField 5 $Acquisition))
    $Rule = Join-TestTigerFields @((New-TestTigerField 1 'Tiger firewall'), (New-TestTigerField 3 'bin/app.exe'), (New-TestTigerField 4 1 0), (New-TestTigerField 5 1 0), (New-TestTigerField 6 1 0), (New-TestTigerField 7 '80,443,8000-8010'))
    $Stop = Join-TestTigerFields @((New-TestTigerField 1 'probe'), (New-TestTigerField 2 5 0), (New-TestTigerField 4 1 0), (New-TestTigerField 5 'C:\Tools\stop.exe'))
    $Resume = Join-TestTigerFields @((New-TestTigerField 1 'probe'), (New-TestTigerField 2 6 0), (New-TestTigerField 4 1 0), (New-TestTigerField 5 'C:\Tools\start.exe'))
    $Quiescence = Join-TestTigerFields @((New-TestTigerField 1 'probe'), (New-TestTigerField 3 $Stop), (New-TestTigerField 4 $Resume), (New-TestTigerField 5 3 0))
    $Launch = Join-TestTigerFields @((New-TestTigerField 1 'bin/app.exe'), (New-TestTigerField 3 'bin'))
    $Legacy = Join-TestTigerFields @((New-TestTigerField 1 'inno'), (New-TestTigerField 2 'Old_is1'))
    $Extra = Join-TestTigerFields @((New-TestTigerField 14 $Legacy), (New-TestTigerField 15 $Dependency), (New-TestTigerField 21 $Rule), (New-TestTigerField 24 $Quiescence), (New-TestTigerField 26 $Launch))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'resources.exe') -FilePath 'bin/app.exe' -ExtraMetadata $Extra
    $Info = Get-TigerSetupInfo $Path
    $Info.SystemEffects.FirewallRules[0].local_ports | Should -Be '80,443,8000-8010'
    $Info.Metadata.launch.PresentFields.Contains('working_directory') | Should -BeTrue
    $Info.Diagnostics.Id | Should -Contain TigerSetup.Legacy.ExistingState
    $Info.Diagnostics.Id | Should -Contain TigerSetup.Actions.ExternalEffects
  }
  It 'Uses last-wins label-map semantics rather than an earlier duplicate value' {
    $Empty = Join-TestTigerFields @((New-TestTigerField 1 'en-US'), (New-TestTigerField 2 ''))
    $Label = Join-TestTigerFields @((New-TestTigerField 1 'en-US'), (New-TestTigerField 2 'Label'))
    $Option = Join-TestTigerFields @((New-TestTigerField 1 'extra'), (New-TestTigerField 4 $Empty), (New-TestTigerField 4 $Label))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'labels.exe') -ExtraMetadata (New-TestTigerField 9 $Option)
    Test-TigerSetupInstaller $Path | Should -BeTrue
    $Option = Join-TestTigerFields @((New-TestTigerField 1 'extra'), (New-TestTigerField 4 $Label), (New-TestTigerField 4 $Empty))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'labels-empty.exe') -ExtraMetadata (New-TestTigerField 9 $Option)
    { Get-TigerSetupInfo $Path } | Should -Throw '*en-US label*'
  }
  It 'Preserves scope-dependent custom ARP tuples rather than deduplicating by ProductCode alone' {
    $Write = Join-TestTigerFields @((New-TestTigerField 1 'Microsoft\Windows\CurrentVersion\Uninstall\ScopeDependent.Tiger'), (New-TestTigerField 2 'DisplayName'), (New-TestTigerField 3 1 0), (New-TestTigerField 4 '%INSTALLROOT%'))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'scope-dependent.exe') -ExtraMetadata (New-TestTigerField 12 $Write)
    $Rows = @((Get-TigerSetupInfo $Path).AppsAndFeaturesEntries | Where-Object ProductCode -EQ ScopeDependent.Tiger)
    $Rows.Count | Should -Be 2
    $Rows.DisplayName | Should -Contain '%LOCALAPPDATA%\Programs\Tiger Test'
    $Rows.DisplayName | Should -Contain '%ProgramFiles%\Tiger Test'
  }
  It 'Preserves empty directories and validates them before output' {
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'empty-dir.exe') -ExtraMetadata (New-TestTigerField 5 (New-TestTigerField 1 'empty/child'))
    $Dest = Join-Path $TestDrive 'empty-dir'
    $null = Expand-TigerSetupInstaller $Path -DestinationPath $Dest
    Test-Path (Join-Path $Dest 'empty/child') -PathType Container | Should -BeTrue
  }
  It 'Exports zero-byte files from an empty <FormatMajor> payload' -ForEach @(@{ FormatMajor = 1 }, @{ FormatMajor = 2 }, @{ FormatMajor = 3 }) {
    $Path = New-TestTigerFixture (Join-Path $TestDrive "zero-$FormatMajor.exe") -FormatMajor $FormatMajor -PayloadData ([byte[]]::new(0))
    $File = Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive "zero-$FormatMajor")
    $File.Length | Should -Be 0
    $File.Name | Should -Be app.txt
  }
  It 'Does not decode unrelated blocks for metadata-only or unmatched selectors' {
    $Bytes = [IO.File]::ReadAllBytes($Script:Fixture)
    $Footer = $Bytes.Length - 320
    $Bytes[[int][BitConverter]::ToUInt64($Bytes, $Footer + 16)] = 0
    $Bytes[[int][BitConverter]::ToUInt64($Bytes, $Footer + 40)] = 0
    $Path = Join-Path $TestDrive 'unrelated-corrupt.exe'
    [IO.File]::WriteAllBytes($Path, $Bytes)
    $Files = @(Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive 'metadata-only') -RawEntries -Name metadata.pb)
    $Files.Count | Should -Be 1
    $Files[0].Name | Should -Be metadata.pb
    @(Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive 'unmatched') -Name absent).Count | Should -Be 0
    Test-Path (Join-Path $TestDrive 'unmatched') | Should -BeFalse
    { Expand-TigerSetupInstaller $Path -DestinationPath $TestDrive } | Should -Throw '*SHA256*'
  }
  It 'Preserves existing files when a late engine verification or staged copy fails' {
    $Dest = Join-Path $TestDrive 'preserved'
    $null = New-Item (Join-Path $Dest 'bin') -ItemType Directory -Force
    $Existing = Join-Path $Dest 'bin/app.txt'
    [IO.File]::WriteAllText($Existing, 'original')
    $Bytes = [IO.File]::ReadAllBytes($Script:Fixture)
    $Bytes[[int][BitConverter]::ToUInt64($Bytes, $Bytes.Length - 320 + 16)] = 0
    $Path = Join-Path $TestDrive 'bad-engine.exe'
    [IO.File]::WriteAllBytes($Path, $Bytes)
    { Expand-TigerSetupInstaller $Path -DestinationPath $Dest -RawEntries -CollisionAction Overwrite } | Should -Throw '*SHA256*'
    [IO.File]::ReadAllText($Existing) | Should -Be original
    Mock Write-TigerSetupStagedFile -ModuleName TigerSetup { throw 'injected copy failure' }
    { Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $Dest -CollisionAction Overwrite } | Should -Throw '*injected*'
    [IO.File]::ReadAllText($Existing) | Should -Be original
    @(Get-ChildItem $Dest -Force -Filter '.tigersetup-stage-*').Count | Should -Be 0
  }
  It 'Rejects junction destinations rather than writing outside the output tree' {
    $Outside = Join-Path $TestDrive 'outside'
    $null = New-Item $Outside -ItemType Directory
    $Dest = Join-Path $TestDrive 'junction'
    $null = New-Item $Dest -ItemType Junction -Target $Outside
    { Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $Dest } | Should -Throw '*reparse point*'
    @(Get-ChildItem $Outside).Count | Should -Be 0
  }
  It 'Streams a payload above the seekable memory threshold and matches exact bytes' {
    $Data = [byte[]]::new(20MB)
    $Data[0] = 17; $Data[-1] = 71
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'large.exe') -PayloadData $Data
    $File = Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive 'large') -MaximumBytes 32MB
    $File.Length | Should -Be 20MB
    (Get-FileHash $File.FullName).Hash | Should -Be ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Data)))
  }
  It 'Uses compiled registration overrides and preserves dual-scope alternatives' {
    $Info = Get-TigerSetupInfo $Script:Fixture
    $Info.ProductCode | Should -Be 'Custom.Tiger'
    $Info.DisplayName | Should -Be 'ARP Tiger'
    $Info.DisplayVersion | Should -Be '4.5.6'
    $Info.ProductVersion | Should -Be '1.2.3'
    $Info.Scope | Should -BeNullOrEmpty
    $Info.ARPEntries.Count | Should -Be 2
    $Info.ARPEntries[0].Values.UninstallString | Should -Be '"%LOCALAPPDATA%\TigerSetup\Vendor.Tiger\uninstall.exe"'
    $Info.ARPEntries[1].RegistryHive | Should -Be 'HKLM'
    $Info.ARPEntries[1].Values.VersionMajor | Should -Be 1
    $Info.ARPEntries[1].Values.InstallLocation | Should -Be '%ProgramFiles%\Tiger Test\'
    $Info.Diagnostics[0].Scenario | Should -BeNullOrEmpty
  }
  It 'Uses explicit scope, option predicates, and the correct state directory' {
    $Info = Get-TigerSetupInfo $Script:Fixture -Scope machine -Option @{ links = 'off' }
    $Info.Scope | Should -Be machine
    $Info.ElevationRequirement | Should -Be elevatesSelf
    $Info.Protocols.Count | Should -Be 0
    $Info.FileExtensions.Count | Should -Be 0
    $Info.ARPEntries[0].Values.QuietUninstallString | Should -Be '"%PROGRAMDATA%\TigerSetup\Vendor.Tiger\uninstall.exe" uninstall --quiet'
    { Get-TigerSetupInfo $Script:Fixture -Option @{ links = 'invalid' } } | Should -Throw '*Boolean*'
    { Get-TigerSetupInfo $Script:Fixture -Option @{ absent = 'on' } } | Should -Throw '*Unknown*'
  }
  It 'Interprets authored scope/option arguments without executing them' {
    $Info = Get-TigerSetupInfo $Script:Fixture -CommandLine 'install --quiet --scope=machine --option links off --log "C:\log dir\setup.log"'
    $Info.Scope | Should -Be machine
    $Info.Protocols.Count | Should -Be 0
    (Get-WinGetInstallerAnalysis -Path $Script:Fixture -CommandLine 'install --quiet --scope user').SuggestedManifestFields.Scope | Should -Be user
    { Get-TigerSetupInfo $Script:Fixture -Scope user -CommandLine '--scope machine' } | Should -Throw '*conflicting*'
  }
  It 'Applies absolute install-root overrides to locations, icons and registry templates' {
    $Write = Join-TestTigerFields @((New-TestTigerField 1 'Microsoft\Windows\CurrentVersion\Uninstall\Custom.Tiger'), (New-TestTigerField 2 'Comments'), (New-TestTigerField 3 1 0), (New-TestTigerField 4 '%INSTALLROOT%/%VERSION%'))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'root.exe') -ExtraMetadata (New-TestTigerField 12 $Write)
    $Info = Get-TigerSetupInfo $Path -CommandLine 'install --quiet --scope=user --install-root="C:\Custom Root" --option=links off'
    $Info.DefaultInstallLocation | Should -Be 'C:\Custom Root'
    $Info.ARPEntries[0].Values.InstallLocation | Should -Be 'C:\Custom Root\'
    $Info.ARPEntries[0].Values.DisplayIcon | Should -Be 'C:\Custom Root\bin\app.txt'
    $Info.ARPEntries[0].Values.Comments | Should -Be 'C:\Custom Root/1.2.3'
    $Info.Protocols.Count | Should -Be 0
    { Get-TigerSetupInfo $Path -CommandLine '--install-root relative' } | Should -Throw '*absolute*'
    { Get-TigerSetupInfo $Path -CommandLine '--install-root' } | Should -Throw '*absolute*'
    { Get-TigerSetupInfo $Path -CommandLine '--scope user --scope user' } | Should -Throw '*Repeated*'
    { Get-TigerSetupInfo $Path -CommandLine '--option=links' } | Should -Throw '*Incomplete*'
  }
  It 'Preserves literal registry strings instead of treating them as paths' {
    $Url = Join-TestTigerFields @((New-TestTigerField 1 'Microsoft\Windows\CurrentVersion\Uninstall\Custom.Tiger'), (New-TestTigerField 2 'URLInfoAbout'), (New-TestTigerField 3 1 0), (New-TestTigerField 4 'https://example.test/help/a'))
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'url.exe') -ExtraMetadata (New-TestTigerField 12 $Url)
    (Get-TigerSetupInfo $Path -Scope user).ARPEntries[0].Values.URLInfoAbout | Should -Be 'https://example.test/help/a'
  }
  It 'Handles source-history builder <BuilderVersion> with its own format <FormatMajor> route' -ForEach @(
    @{ BuilderVersion = '0.5.2'; FormatMajor = 1 }, @{ BuilderVersion = '0.5.3'; FormatMajor = 1 },
    @{ BuilderVersion = '0.6.0'; FormatMajor = 1 }, @{ BuilderVersion = '0.7.0'; FormatMajor = 1 },
    @{ BuilderVersion = '0.7.1'; FormatMajor = 1 }, @{ BuilderVersion = '0.8.0'; FormatMajor = 2 },
    @{ BuilderVersion = '0.9.0'; FormatMajor = 3 }, @{ BuilderVersion = '0.10.0'; FormatMajor = 3 },
    @{ BuilderVersion = '0.11.0'; FormatMajor = 3 }
  ) {
    $Path = New-TestTigerFixture (Join-Path $TestDrive "history-$BuilderVersion.exe") -FormatMajor $FormatMajor -BuilderVersion $BuilderVersion
    Test-TigerSetupInstaller $Path | Should -BeTrue
    $Info = Get-TigerSetupInfo $Path -CommandLine 'install --quiet --scope user --install-root "C:\Historical Root"'
    $Info.FormatVersion | Should -Be "$FormatMajor.0"
    $Info.MetadataSchema | Should -Be ($FormatMajor -eq 3 ? 2 : 1)
    $Info.ParserVersionInfo.BuilderVersion | Should -Be $BuilderVersion
    $Info.ProductCode | Should -Be Custom.Tiger
    $Info.ARPEntries[0].Values.InstallLocation | Should -Be 'C:\Historical Root\'
    $Info.ARPEntries[0].Values.QuietUninstallString | Should -Be '"%LOCALAPPDATA%\TigerSetup\Vendor.Tiger\uninstall.exe" uninstall --quiet'
    $Info.PayloadCatalog.Count | Should -Be 1
    $Info.Diagnostics.Id | Should -Not -Contain TigerSetup.Metadata.FutureFields
    $Output = Join-Path $TestDrive "history-$BuilderVersion"
    $Files = @(Expand-TigerSetupInstaller $Path -DestinationPath $Output -IncludeUninstaller -Scope user -RawEntries)
    [IO.File]::ReadAllText((Join-Path $Output 'bin/app.txt')) | Should -Be 'Tiger payload'
    $Uninstaller = $Files | Where-Object Name -EQ uninstall.exe
    $UninstallInfo = Get-TigerSetupInfo $Uninstaller.FullName
    $UninstallInfo.Role | Should -Be Uninstaller
    $UninstallInfo.FormatVersion | Should -Be "$FormatMajor.0"
    $UninstallInfo.Scope | Should -Be user
    $UninstallInfo.PayloadCatalog.Count | Should -Be 0
    $UninstallInfo.WritesAppsAndFeaturesEntry | Should -BeFalse
    Test-TigerSetupInstaller $Uninstaller.FullName | Should -BeFalse
    $Fields = (Get-WinGetInstallerAnalysis -Path $Path -CommandLine 'install --quiet --scope user').SuggestedManifestFields
    $Fields.Scope | Should -Be user
    $Fields.InstallerSwitches.Silent | Should -Be 'install --quiet'
  }
  It 'Locates signed historical footer <FormatMajor> without scanning the overlay' -ForEach @( @{ FormatMajor = 1 }, @{ FormatMajor = 2 } ) {
    $Path = New-TestTigerFixture (Join-Path $TestDrive "signed-$FormatMajor.exe") -FormatMajor $FormatMajor -Signed
    (Get-TigerSetupInfo $Path).FormatVersion | Should -Be "$FormatMajor.0"
    $Output = Join-Path $TestDrive "signed-history-$FormatMajor"
    $Uninstaller = Expand-TigerSetupInstaller $Path -DestinationPath $Output -IncludeUninstaller -Scope machine | Where-Object Name -EQ uninstall.exe
    (Get-TigerSetupInfo $Uninstaller.FullName).Scope | Should -Be machine
  }
  It 'Rejects cross-generation schemas and legacy footer corruption <FormatMajor>' -ForEach @( @{ FormatMajor = 1 }, @{ FormatMajor = 2 }, @{ FormatMajor = 3 } ) {
    $Path = New-TestTigerFixture (Join-Path $TestDrive "wrong-schema-$FormatMajor.exe") -FormatMajor $FormatMajor -SchemaVersion ($FormatMajor -eq 3 ? 1 : 2)
    { Get-TigerSetupInfo $Path } | Should -Throw '*schema*'
    $Path = New-TestTigerFixture (Join-Path $TestDrive "crc-$FormatMajor.exe") -FormatMajor $FormatMajor
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $Bytes[$Bytes.Length - @(0, 128, 256, 320)[$FormatMajor] + 16] = $Bytes[$Bytes.Length - @(0, 128, 256, 320)[$FormatMajor] + 16] -bxor 1
    [IO.File]::WriteAllBytes($Path, $Bytes)
    { Get-TigerSetupInfo $Path } | Should -Throw '*CRC32*'
  }
  It 'Handles stored ZIP files and verifies the entire legacy archive hash' {
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'stored-zip.exe') -FormatMajor 1 -ZipCompression NoCompression
    $File = Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive 'stored-zip')
    [IO.File]::ReadAllText($File.FullName) | Should -Be 'Tiger payload'
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $PayloadOffset = [BitConverter]::ToUInt64($Bytes, $Bytes.Length - 128 + 32)
    $Bytes[$PayloadOffset + 30 + 4] = $Bytes[$PayloadOffset + 30 + 4] -bxor 1
    [IO.File]::WriteAllBytes($Path, $Bytes)
    { Expand-TigerSetupInstaller $Path -DestinationPath $TestDrive } | Should -Throw '*payload SHA256*'
  }
  It 'Checks legacy entry CRC even when the enclosing archive hash is consistent' {
    $Path = New-TestTigerFixture (Join-Path $TestDrive 'crc-zip.exe') -FormatMajor 1 -ZipCompression NoCompression
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $FooterOffset = $Bytes.Length - 128
    $Offset = [int][BitConverter]::ToUInt64($Bytes, $FooterOffset + 32)
    $Length = [int][BitConverter]::ToUInt64($Bytes, $FooterOffset + 40)
    $DataOffset = $Offset + 30 + [BitConverter]::ToUInt16($Bytes, $Offset + 26) + [BitConverter]::ToUInt16($Bytes, $Offset + 28)
    $Bytes[$DataOffset] = $Bytes[$DataOffset] -bxor 1
    $ZipStream = [IO.MemoryStream]::new($Bytes, $Offset, $Length, $false)
    try { [Security.Cryptography.SHA256]::HashData($ZipStream).CopyTo($Bytes, $FooterOffset + 80) } finally { $ZipStream.Dispose() }
    [BitConverter]::GetBytes((Get-BinaryCrc32 -Bytes $Bytes -Offset $FooterOffset -Count 116)).CopyTo($Bytes, $FooterOffset + 116)
    [IO.File]::WriteAllBytes($Path, $Bytes)
    { Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive 'bad-zip-crc') } | Should -Throw '*CRC*'
    Test-Path (Join-Path $TestDrive 'bad-zip-crc/bin/app.txt') | Should -BeFalse
  }
  It 'Extracts all files with omitted Name and prompts only after a collision' {
    $Dest = Join-Path $TestDrive 'all'
    $Files = @(Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $Dest)
    $Files.Count | Should -Be 1
    [IO.File]::ReadAllText($Files[0].FullName) | Should -Be 'Tiger payload'
    { Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $Dest -CollisionAction Error } | Should -Throw '*already exists*'
    @(Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $Dest -CollisionAction Skip).Count | Should -Be 0
    @(Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $Dest -CollisionAction Rename).Count | Should -Be 1
    @(Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $Dest -Name absent -CollisionAction Error).Count | Should -Be 0
  }
  It 'Rejects bad region checksums before creating output' -ForEach @(@{ BadEntryCrc = $true; BadHash = $false; Expected = '*CRC32*' }, @{ BadEntryCrc = $false; BadHash = $true; Expected = '*SHA256*' }) {
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive "$BadEntryCrc-$BadHash.exe") -BadEntryCrc:$BadEntryCrc -BadHash:$BadHash
    { Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive "bad-$BadEntryCrc") } | Should -Throw $Expected
  }
  It 'Rejects traversal, excessive output, and unsupported scope' {
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive 'traversal.exe') -FilePath '../escape.txt'
    Test-TigerSetupInstaller $Path | Should -BeFalse
    { Expand-TigerSetupInstaller $Script:Fixture -DestinationPath $TestDrive -MaximumBytes 1 } | Should -Throw '*limit*'
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive 'user.exe') -Scopes @(1)
    (Get-TigerSetupInfo $Path).Scope | Should -Be user
    { Get-TigerSetupInfo $Path -Scope machine } | Should -Throw '*does not support*'
  }
  It 'Locates a signed logical ending and reconstructs a payload-free uninstaller' {
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive 'signed.exe') -Signed
    Test-TigerSetupInstaller $Path | Should -BeTrue
    $Files = @(Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive 'signed') -IncludeUninstaller -Scope user)
    $Uninstall = $Files | Where-Object Name -EQ uninstall.exe
    $Info = Get-TigerSetupInfo $Uninstall.FullName
    $Info.Role | Should -Be Uninstaller
    $Info.Scope | Should -Be user
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    Test-TigerSetupInstaller $Uninstall.FullName | Should -BeFalse
  }
  It 'Rejects marker-only files, footer corruption and truncated Protobuf' {
    $Path = Join-Path $TestDrive 'marker.exe'
    [IO.File]::WriteAllText($Path, 'TIGERSTP PTSREGIT')
    Test-TigerSetupInstaller $Path | Should -BeFalse
    $Bytes = [IO.File]::ReadAllBytes($Script:Fixture)
    $Bytes[$Bytes.Length - 320 + 80] = $Bytes[$Bytes.Length - 320 + 80] -bxor 1
    [IO.File]::WriteAllBytes($Path, $Bytes)
    { Get-TigerSetupInfo $Path } | Should -Throw '*footer CRC32*'
    { [Dumplings.TigerSetup.MetadataReader]::Read([byte[]](18, 127, 1)) } | Should -Throw '*length*'
    { [Dumplings.TigerSetup.MetadataReader]::Read([byte[]](0)) } | Should -Throw '*field number*'
  }
  It 'Preserves unknown fields as unresolved forward-compatible evidence' {
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive 'future.exe') -ExtraMetadata (New-TestTigerField 99 'future')
    (Get-TigerSetupInfo $Path).Diagnostics.Id | Should -Contain TigerSetup.Metadata.FutureFields
  }
  It 'Keeps hidden/custom ARP rows out of the built-in visible identity' {
    $Hide = Join-TestTigerFields @((New-TestTigerField 1 'Microsoft\Windows\CurrentVersion\Uninstall\Custom.Tiger'), (New-TestTigerField 2 'SystemComponent'), (New-TestTigerField 3 3 0), (New-TestTigerField 4 '1'))
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive 'hidden.exe') -ExtraMetadata (New-TestTigerField 12 $Hide)
    $Info = Get-TigerSetupInfo $Path
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.ARPEntries.IsVisible | Should -Not -Contain $true
    $Info.CanExpand | Should -BeTrue
    $Custom = Join-TestTigerFields @((New-TestTigerField 1 'Microsoft\Windows\CurrentVersion\Uninstall\Second.Tiger'), (New-TestTigerField 2 'DisplayName'), (New-TestTigerField 3 1 0), (New-TestTigerField 4 'Custom visible'))
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive 'custom.exe') -ExtraMetadata (Join-TestTigerFields @((New-TestTigerField 12 $Hide), (New-TestTigerField 12 $Custom)))
    $Info = Get-TigerSetupInfo $Path -Scope user
    $Info.AppsAndFeaturesEntries.ProductCode | Should -Be 'Second.Tiger'
    $Info.AppsAndFeaturesEntries.DisplayName | Should -Be 'Custom visible'
  }
  It 'Reads choices, localized labels and nested unknown fields without UTF-8 guessing' {
    $Label = Join-TestTigerFields @((New-TestTigerField 1 'en-US'), (New-TestTigerField 2 'One'))
    $Choice = Join-TestTigerFields @((New-TestTigerField 1 'one'), (New-TestTigerField 2 $Label))
    $Second = Join-TestTigerFields @((New-TestTigerField 1 'two'), (New-TestTigerField 2 $Label))
    $Option = Join-TestTigerFields @((New-TestTigerField 1 'mode'), (New-TestTigerField 3 4 0), (New-TestTigerField 4 $Label), (New-TestTigerField 5 $Choice), (New-TestTigerField 5 $Second), (New-TestTigerField 6 'one'), (New-TestTigerField 99 'future'))
    $Path = New-TestTigerFixture -Path (Join-Path $TestDrive 'choices.exe') -ExtraMetadata (New-TestTigerField 9 $Option)
    $Info = Get-TigerSetupInfo $Path -Option @{ mode = 'ONE' }
    $Info.OptionValues.mode | Should -Be one
    $Info.Metadata.options[1].choices[0].labels[0].value | Should -Be One
    $Info.Diagnostics.Id | Should -Contain TigerSetup.Metadata.FutureFields
    { Get-TigerSetupInfo $Path -Option @{ mode = 'missing' } } | Should -Throw '*choice*'
  }
  It 'Checks compressed hashes, footer bounds and unsupported versions' -ForEach @(
    @{ Case = 'PayloadHash'; Message = '*compressed block SHA256*' },
    @{ Case = 'MetadataHash'; Message = '*metadata SHA256*' },
    @{ Case = 'Offset'; Message = '*outside*' },
    @{ Case = 'Major'; Message = '*Unsupported*' }
  ) {
    $Bytes = [IO.File]::ReadAllBytes($Script:Fixture)
    $Footer = $Bytes.Length - 320
    switch ($Case) {
      PayloadHash { $Position = [int][BitConverter]::ToUInt64($Bytes, $Footer + 40); $Bytes[$Position] = $Bytes[$Position] -bxor 1 }
      MetadataHash { $Bytes[$Footer + 216] = $Bytes[$Footer + 216] -bxor 1 }
      Offset { [BitConverter]::GetBytes([uint64]::MaxValue).CopyTo($Bytes, $Footer + 64) }
      Major { $Bytes[$Footer + 8] = 4 }
    }
    [BitConverter]::GetBytes((Get-BinaryCrc32 -Bytes $Bytes -Offset $Footer -Count 308)).CopyTo($Bytes, $Footer + 308)
    $Path = Join-Path $TestDrive "$Case.exe"
    [IO.File]::WriteAllBytes($Path, $Bytes)
    if ($Case -eq 'PayloadHash') { { Expand-TigerSetupInstaller $Path -DestinationPath $TestDrive } | Should -Throw $Message }
    else { { Get-TigerSetupInfo $Path } | Should -Throw $Message }
  }
  It 'Rejects overflowing varints, wrong wire types and invalid UTF-8' {
    { [Dumplings.TigerSetup.MetadataReader]::Read([byte[]](8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2)) } | Should -Throw '*varint*'
    { [Dumplings.TigerSetup.MetadataReader]::Read([byte[]](10, 0)) } | Should -Throw '*wire type*'
    $Package = New-TestTigerField 1 ([byte[]](255))
    { [Dumplings.TigerSetup.MetadataReader]::Read((New-TestTigerField 2 $Package)) } | Should -Throw
  }
  It 'Resolves PowerShell-relative paths and exposes raw engine/metadata without execution' {
    Push-Location $TestDrive
    try {
      (Get-TigerSetupInfo './setup.exe').Path | Should -Be $Script:Fixture
      $Files = @(Expand-TigerSetupInstaller './setup.exe' -DestinationPath './raw' -RawEntries)
      $Files.Name | Should -Contain engine.exe
      $Files.Name | Should -Contain metadata.pb
      $Files.Count | Should -Be 4
    } finally { Pop-Location }
  }
  It 'Projects schema-valid scope variants and routes authoring to TigerSetup' {
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:Fixture
    $Analysis.ParserResults.Name | Should -Contain TigerSetup
    $Analysis.SuggestedManifestVariants.Count | Should -Be 2
    $Machine = $Analysis.SuggestedManifestVariants | Where-Object Name -EQ machine
    $Machine.ManifestFields.InstallerSwitches.Custom | Should -Be '--scope machine'
    $Machine.ManifestFields.ElevationRequirement | Should -Be elevatesSelf
    $Analysis.SuggestedManifestFields.ExpectedReturnCodes.InstallerReturnCode | Should -Contain 3010
    $Schema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion '1.12.0'
    foreach ($Variant in $Analysis.SuggestedManifestVariants) {
      $Entry = [ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64 }
      foreach ($Property in $Variant.ManifestFields.PSObject.Properties) { $Entry[$Property.Name] = $Property.Value }
      (Get-YamlSchemaValidationResult -InputObject $Entry -Schema $Schema.definitions.Installer -RootSchema $Schema -ValidatePropertyNames).IsValid | Should -BeTrue
    }
    $Generic = Get-InstallerAnalysis -Path $Script:Fixture
    $Generic.PSObject.Properties.Name | Should -Not -Contain SuggestedManifestFields
  }
  It 'Updates existing installer identity/location through the normal manifest pipeline' {
    $Result = & (Get-Module WinGetManifestUpdate) {
      param($Path)
      $Installer = [ordered]@{ Architecture = 'x64'; InstallerType = 'exe'; Scope = 'user'; InstallerUrl = 'https://example.test/setup.exe'; ProductCode = 'Old.Tiger'; InstallationMetadata = [ordered]@{ DefaultInstallLocation = '%LOCALAPPDATA%\Old' }; InstallerSwitches = [ordered]@{ Silent = 'install --quiet'; Custom = '--scope user' }; AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Old Tiger'; DisplayVersion = '0.0.0'; ProductCode = 'Old.Tiger' }) }
      Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller (Copy-Object $Installer) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{ 'https://example.test/setup.exe' = $Path }) -Logger { param($Message, $Level) }
    } $Script:Fixture
    $Result.ProductCode | Should -Be Custom.Tiger
    $Result.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'ARP Tiger'
    $Result.AppsAndFeaturesEntries[0].DisplayVersion | Should -Be '4.5.6'
    $Result.InstallationMetadata.DefaultInstallLocation | Should -Be '%LOCALAPPDATA%\Programs\Tiger Test'
    $Result.Scope | Should -Be user
    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerPath $Script:Fixture -InstallerUrl 'https://example.test/setup.exe'
    $Suggestion.Installers[0].ProductCode | Should -Be Custom.Tiger
    $Suggestion.HasBlockingDiagnostics | Should -BeFalse
  }
  It 'Reuses the managed reader across concurrent runspaces' {
    $Jobs = @()
    try {
      for ($Index = 0; $Index -lt 3; $Index++) {
        $Jobs += Start-ThreadJob -ScriptBlock {
          param($ModulePath, $Installer)
          Import-Module $ModulePath -ErrorAction Stop
          (Get-TigerSetupInfo -Path $Installer).ProductCode
        } -ArgumentList ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\PackageModule.psd1'))), $Script:Fixture
      }
      $Result = @($Jobs | Wait-Job | Receive-Job -ErrorAction Stop)
      $Result.Count | Should -Be 3
      $Result | Should -Not -Contain $null
      foreach ($Value in $Result) { $Value | Should -Be Custom.Tiger }
    } finally { $Jobs | Remove-Job -Force }
  }
}

Describe 'Published TigerSetup regressions' {
  It 'Matches the controlled VM-validated rich registration and system-effect fixture' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\TigerSetup\0.14.0\Rich\Probe.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Controlled rich fixture is not cached.'; return }
    (Get-DumplingsTestFixtureHash $Path) | Should -Be '0BFDCA8BD0E3B765DBD89F210BCBC6C58AA840D464B85209A4550B914CC2B88D'
    $User = Get-TigerSetupInfo $Path -Scope user
    $User.AppsAndFeaturesEntries.ProductCode | Should -Contain Research.TigerRemaining.Arp
    $User.AppsAndFeaturesEntries.ProductCode | Should -Contain Research.TigerRemaining.Custom
    $User.SystemEffects.EnvironmentVariables[0].name | Should -Be DUMPLINGS_TIGER_REMAINING
    $User.FileExtensions | Should -Be dumplingstigerremaining
    $User.Protocols | Should -Be dumplings-tiger-remaining
    $User.DependencyInfo.EmbeddedPackages.Count | Should -Be 1
    $User.SystemEffects.Actions[0].name | Should -Be probe-noop
    $User.Metadata.launch.PresentFields.Contains('working_directory') | Should -BeFalse
    $Hidden = Get-TigerSetupInfo $Path -Scope machine -Option @{ 'hidden-arp' = 'on' }
    $Hidden.ProductCode | Should -BeNullOrEmpty
    $Hidden.AppsAndFeaturesEntries.ProductCode | Should -Be Research.TigerRemaining.Custom
    ($Hidden.ARPEntries | Where-Object ProductCode -EQ Research.TigerRemaining.Arp).IsVisible | Should -BeFalse
    $Files = @(Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive 'rich') -RawEntries -Name '*.exe')
    $Files.Name | Should -Contain probe.exe
    $Files.Name | Should -Contain Prerequisite.exe
  }
  It 'Parses and extracts published format-3/schema-2 release <Version>' -ForEach @(
    @{ Version = '0.12.0'; Hash = '9FCAE32789A494A96A3E04B8DE2AFB6691831F6C8E68625A441DED57EACEB765' },
    @{ Version = '0.13.0'; Hash = '5F0EA8C40911436DCC5A62EC7C76AF0A614766DC5AD5739CCA1DB8C3ABFB6104' },
    @{ Version = '0.14.0'; Hash = '9D6E322A8EA3205F8E32EEDABD4230A9BE90157334359682D18DF7A4F9322C20' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath "Installers\TigerSetup\IT-Tiger.TigerSetup\$Version\TigerSetup-$Version-Setup.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'Published fixture is not cached.'; return }
    (Get-DumplingsTestFixtureHash -Path $Path) | Should -Be $Hash
    $Info = Get-TigerSetupInfo $Path
    $Info.ProductCode | Should -Be ItTiger.TigerSetup
    $Info.ProductVersion | Should -Be $Version
    $Files = @(Expand-TigerSetupInstaller $Path -DestinationPath (Join-Path $TestDrive $Version) -Name tiger-setup.exe)
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -BeGreaterThan 100000
  }
}
