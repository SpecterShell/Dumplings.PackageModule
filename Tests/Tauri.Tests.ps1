BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')

  $Script:TauriFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\Tauri'
  $Script:TauriSyntheticDirectory = Join-Path $Script:TauriFixtureDirectory 'Synthetic'
  if (Test-Path -LiteralPath $Script:TauriSyntheticDirectory) {
    Remove-Item -LiteralPath $Script:TauriSyntheticDirectory -Recurse -Force
  }
  $null = New-Item -Path $Script:TauriSyntheticDirectory -ItemType Directory -Force

  function Compress-TestTauriBrotli {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    $Output = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.BrotliStream]::new($Output, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try { $Encoder.Write($Bytes, 0, $Bytes.Length) } finally { $Encoder.Dispose() }
    return , $Output.ToArray()
  }

  function New-TestTauriAsset {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Content,
      [ValidateSet('Brotli', 'None')][string]$Compression = 'Brotli'
    )
    [pscustomobject]@{ Name = $Name; Content = $Content; Compression = $Compression }
  }

  function New-TestTauriExecutable {
    param(
      [Parameter(Mandatory)][string]$Name,
      [uint16]$Machine = 0x8664,
      [switch]$PE32,
      [switch]$Dll,
      [object[]]$AssetMap,
      [string[]]$Marker = @('tauri://localhost', '__TAURI_INTERNALS__', '__TAURI_BUNDLE_TYPE_VAR_NSS')
    )

    if ($null -eq $AssetMap) {
      $AssetMap = @([pscustomobject]@{ Assets = @(
            (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<!doctype html><html>Tauri fixture</html>')))
            (New-TestTauriAsset -Name '/assets/app.js' -Content ([Text.Encoding]::UTF8.GetBytes('globalThis.__TAURI_FIXTURE__ = true;')))
          )
        })
    }

    $Path = Join-Path $Script:TauriSyntheticDirectory $Name
    $Bytes = [byte[]]::new(0x60000)
    $PeOffset = 0x80
    $OptionalHeaderOffset = $PeOffset + 24
    $OptionalHeaderSize = if ($PE32) { 0xE0 } else { 0xF0 }
    $SectionOffset = $OptionalHeaderOffset + $OptionalHeaderSize
    $ImageBase = if ($PE32) { [uint64]0x00400000 } else { [uint64]0x0000000140000000 }
    $PointerSize = if ($PE32) { 4 } else { 8 }
    $RecordSize = $PointerSize * 4

    function Write-TestUInt16([int]$Offset, [uint16]$Value) { [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    function Write-TestUInt32([int]$Offset, [uint32]$Value) { [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    function Write-TestUInt64([int]$Offset, [uint64]$Value) { [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    function Write-TestBytes([int]$Offset, [byte[]]$Value) { [Array]::Copy($Value, 0, $Bytes, $Offset, $Value.Length) }
    function Convert-TestOffsetToVa([int]$Offset) { [uint64]($ImageBase + 0x1000 + $Offset - 0x200) }
    function Write-TestPointer([int]$Offset, [uint64]$Value) {
      if ($PointerSize -eq 4) { Write-TestUInt32 $Offset ([uint32]$Value) } else { Write-TestUInt64 $Offset $Value }
    }

    Write-TestUInt16 0 0x5A4D
    Write-TestUInt32 0x3C $PeOffset
    Write-TestUInt32 $PeOffset 0x00004550
    Write-TestUInt16 ($PeOffset + 4) $Machine
    Write-TestUInt16 ($PeOffset + 6) 1
    Write-TestUInt16 ($PeOffset + 20) $OptionalHeaderSize
    $Characteristics = if ($Dll) { [uint16]0x2102 } else { [uint16]0x0102 }
    $OptionalHeaderMagic = if ($PE32) { [uint16]0x010B } else { [uint16]0x020B }
    Write-TestUInt16 ($PeOffset + 22) $Characteristics
    Write-TestUInt16 $OptionalHeaderOffset $OptionalHeaderMagic
    if ($PE32) { Write-TestUInt32 ($OptionalHeaderOffset + 28) ([uint32]$ImageBase) }
    else { Write-TestUInt64 ($OptionalHeaderOffset + 24) $ImageBase }
    Write-TestUInt32 ($OptionalHeaderOffset + 56) 0x61000
    Write-TestUInt32 ($OptionalHeaderOffset + 60) 0x200
    Write-TestUInt16 ($OptionalHeaderOffset + 68) 2
    $NumberOfRvaAndSizesOffset = $OptionalHeaderOffset + $(if ($PE32) { 92 } else { 108 })
    Write-TestUInt32 $NumberOfRvaAndSizesOffset 16

    Write-TestBytes $SectionOffset ([Text.Encoding]::ASCII.GetBytes('.rdata'))
    Write-TestUInt32 ($SectionOffset + 8) 0x5FE00
    Write-TestUInt32 ($SectionOffset + 12) 0x1000
    Write-TestUInt32 ($SectionOffset + 16) 0x5FE00
    Write-TestUInt32 ($SectionOffset + 20) 0x200

    $RecordOffset = 0x400
    $NameOffset = 0x20000
    $DataOffset = 0x30000
    foreach ($Map in $AssetMap) {
      foreach ($Asset in $Map.Assets) {
        $NameBytes = [Text.Encoding]::UTF8.GetBytes([string]$Asset.Name)
        $StoredBytes = if ($Asset.Compression -eq 'Brotli') { Compress-TestTauriBrotli -Bytes $Asset.Content } else { [byte[]]$Asset.Content }
        Write-TestBytes $NameOffset $NameBytes
        if ($StoredBytes.Length -gt 0) { Write-TestBytes $DataOffset $StoredBytes }
        Write-TestPointer $RecordOffset (Convert-TestOffsetToVa $NameOffset)
        Write-TestPointer ($RecordOffset + $PointerSize) $NameBytes.Length
        # Empty Rust slices use a dangling pointer and never dereference it.
        $PayloadPointer = if ($StoredBytes.Length -eq 0) { [uint64]1 } else { Convert-TestOffsetToVa $DataOffset }
        Write-TestPointer ($RecordOffset + ($PointerSize * 2)) $PayloadPointer
        Write-TestPointer ($RecordOffset + ($PointerSize * 3)) $StoredBytes.Length
        $RecordOffset += $RecordSize
        $NameOffset += $NameBytes.Length + 16
        $DataOffset += $StoredBytes.Length + 16
      }
      $RecordOffset += 0x80
    }

    $MarkerOffset = 0x18000
    foreach ($Value in $Marker) {
      $MarkerBytes = [Text.Encoding]::ASCII.GetBytes($Value)
      Write-TestBytes $MarkerOffset $MarkerBytes
      $MarkerOffset += $MarkerBytes.Length + 8
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)
    return $Path
  }
}

Describe 'Tauri executable structure and metadata' {
  It 'parses PE32 x86 raw maps, Unicode paths, and empty assets' {
    $Maps = @([pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>raw</html>')) -Compression None)
          (New-TestTauriAsset -Name '/assets/你好.txt' -Content ([Text.Encoding]::UTF8.GetBytes('Unicode asset')) -Compression None)
          (New-TestTauriAsset -Name '/empty.txt' -Content ([byte[]]::new(0)) -Compression None)
        )
      })
    $Path = New-TestTauriExecutable -Name 'tauri-x86-raw.bin' -Machine 0x014C -PE32 -AssetMap $Maps
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.Architecture | Should -Be 'x86'
    $Info.ParserVersionInfo.RecordWidth | Should -Be 16
    $Info.AssetCompression | Should -Be 'None'
    $Info.AssetCount | Should -Be 3
    $Info.AssetDescriptors.Name | Should -Contain '/assets/你好.txt'
    ($Info.AssetDescriptors | Where-Object Name -EQ '/empty.txt').ExpandedSize | Should -Be 0
    $Info.CanExpand | Should -BeTrue
  }

  It 'parses PE32+ x64 and ARM64 Brotli maps and selects the earliest bundle token' -ForEach @(
    @{ Name = 'tauri-x64.exe'; Machine = [uint16]0x8664; Architecture = 'x64' }
    @{ Name = 'tauri-arm64.exe'; Machine = [uint16]0xAA64; Architecture = 'arm64' }
  ) {
    $Path = New-TestTauriExecutable -Name $Name -Machine $Machine -Marker @(
      '__TAURI_BUNDLE_TYPE_VAR_NSS', '__TAURI_BUNDLE_TYPE_VAR_MSI', 'tauri://localhost', '__TAURI_INTERNALS__')
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.Architecture | Should -Be $Architecture
    $Info.ParserVersionInfo.RecordWidth | Should -Be 32
    $Info.AssetCompression | Should -Be 'Brotli'
    $Info.BundleType | Should -Be 'NSIS'
    $Info.Notices | Should -Match 'earliest patched token'
  }

  It 'recognizes multiple maps and preserves duplicate names' {
    $Maps = @(
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>one</html>')))
        )
      }
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>two</html>')))
          (New-TestTauriAsset -Name '/isolation.js' -Content ([Text.Encoding]::UTF8.GetBytes('isolation')))
        )
      }
    )
    $Info = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-multiple.exe' -AssetMap $Maps)

    $Info.AssetMapCount | Should -Be 2
    @($Info.AssetDescriptors | Where-Object Name -EQ '/index.html') | Should -HaveCount 2
  }

  It 'reports marker-only custom providers without claiming expandable assets' {
    $Info = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-marker-only.exe' -AssetMap @())

    $Info.DetectionConfidence | Should -Be 'medium'
    $Info.CanExpand | Should -BeFalse
    $Info.UnresolvedFields | Should -Contain 'EmbeddedAssets'
    $Info.Warnings | Should -Match 'custom or URL-backed asset provider'
  }

  It 'rejects DLLs and unrelated PEs' {
    Test-TauriExecutable -Path (New-TestTauriExecutable -Name 'tauri.dll' -Dll) | Should -BeFalse
    Test-TauriExecutable -Path (Get-Process -Id $PID).Path | Should -BeFalse
  }

  It 'does not promote reverse-domain and ACL strings to authoritative metadata' {
    $Path = New-TestTauriExecutable -Name 'tauri-candidates.exe'
    $Bytes = [IO.File]::ReadAllBytes($Path)
    [Text.Encoding]::ASCII.GetBytes("com.example.product`0core:window:allow-close`0").CopyTo($Bytes, 0x19000)
    [IO.File]::WriteAllBytes($Path, $Bytes)
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.PSObject.Properties.Name | Should -Not -Contain 'PackageIdentifier'
    $Info.PackageIdentifierCandidates.Value | Should -Contain 'com.example.product'
    $Info.AclPermissionCandidates.Value | Should -Contain 'core:window:allow-close'
    $Info.PackageIdentifierCandidates[0].Confidence | Should -Be 'low'
  }

  It 'ignores malformed pointers and invalid UTF-8 records without reading outside the PE' -ForEach @(
    @{ Name = 'tauri-invalid-pointer.exe'; Mutate = 'Pointer' }
    @{ Name = 'tauri-invalid-utf8.exe'; Mutate = 'Utf8' }
  ) {
    $Path = New-TestTauriExecutable -Name $Name
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    try {
      if ($Mutate -eq 'Pointer') {
        $InvalidPointer = [BitConverter]::GetBytes([uint64]::MaxValue)
        foreach ($Offset in 0x400, 0x420) {
          $Stream.Position = $Offset
          $Stream.Write($InvalidPointer, 0, $InvalidPointer.Length)
        }
      } else {
        foreach ($Offset in 0x20000, 0x2001B) {
          $Stream.Position = $Offset
          $Stream.WriteByte(0xFF)
        }
      }
    } finally {
      $Stream.Dispose()
    }

    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.CanExpand | Should -BeFalse
    $Info.AssetCount | Should -Be 0
    $Info.Warnings | Should -Match 'custom or URL-backed asset provider'
  }

}

Describe 'Tauri executable extraction safety' {
  It 'extracts every selected asset and supports leaf-name filtering' {
    $Path = New-TestTauriExecutable -Name 'tauri-expand.exe'
    $Destination = Join-Path $TestDrive 'all-assets'
    $Files = @(Expand-TauriExecutable -Path $Path -DestinationPath $Destination -CollisionAction Rename)
    $IndexOnly = @(Expand-TauriExecutable -Path $Path -DestinationPath (Join-Path $TestDrive 'index-only') -Name 'index.html' -CollisionAction Rename)

    $Files | Should -HaveCount 2
    $IndexOnly | Should -HaveCount 1
    Get-Content -LiteralPath $IndexOnly[0].FullName -Raw | Should -Match 'Tauri fixture'
  }

  It 'applies rename, skip, overwrite, and error collision policies' {
    $Maps = @(
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/same.txt' -Content ([Text.Encoding]::UTF8.GetBytes('one')) -Compression None)
          (New-TestTauriAsset -Name '/first.js' -Content ([Text.Encoding]::UTF8.GetBytes('first')) -Compression None)
        )
      }
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/same.txt' -Content ([Text.Encoding]::UTF8.GetBytes('two')) -Compression None)
          (New-TestTauriAsset -Name '/second.js' -Content ([Text.Encoding]::UTF8.GetBytes('second')) -Compression None)
        )
      }
    )
    $Path = New-TestTauriExecutable -Name 'tauri-collisions.exe' -AssetMap $Maps

    $RenameFiles = @(Expand-TauriExecutable -Path $Path -DestinationPath (Join-Path $TestDrive 'rename') -Name 'same.txt' -CollisionAction Rename)
    $RenameFiles.Name | Should -Be @('same.txt', 'same (1).txt')

    $OverwriteFiles = @(Expand-TauriExecutable -Path $Path -DestinationPath (Join-Path $TestDrive 'overwrite') -Name 'same.txt' -CollisionAction Overwrite)
    $OverwriteFiles | Should -HaveCount 2
    Get-Content -LiteralPath $OverwriteFiles[-1].FullName -Raw | Should -Be 'two'

    $SkipDestination = Join-Path $TestDrive 'skip'
    $null = New-Item -Path $SkipDestination -ItemType Directory
    Set-Content -LiteralPath (Join-Path $SkipDestination 'same.txt') -Value 'existing'
    @(Expand-TauriExecutable -Path $Path -DestinationPath $SkipDestination -Name 'same.txt' -CollisionAction Skip) | Should -HaveCount 0
    { Expand-TauriExecutable -Path $Path -DestinationPath $SkipDestination -Name 'same.txt' -CollisionAction Error } | Should -Throw '*already exists*'
  }

  It 'uses Prompt without prompting when no collision exists' {
    $Path = New-TestTauriExecutable -Name 'tauri-prompt.exe'
    @(Expand-TauriExecutable -Path $Path -DestinationPath (Join-Path $TestDrive 'prompt') -Name 'app.js') | Should -HaveCount 1
  }

  It 'rejects traversal paths, mixed maps, truncated Brotli, and output limits' {
    $UnsafeMaps = @([pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>safe</html>')))
          (New-TestTauriAsset -Name '/../escape.txt' -Content ([Text.Encoding]::UTF8.GetBytes('unsafe')))
        )
      })
    { Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-traversal.exe' -AssetMap $UnsafeMaps) } | Should -Throw '*unsafe path*'

    $MixedMaps = @([pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>mixed</html>')))
          (New-TestTauriAsset -Name '/app.js' -Content ([Text.Encoding]::UTF8.GetBytes('raw')) -Compression None)
        )
      })
    $MixedPath = New-TestTauriExecutable -Name 'tauri-mixed.exe' -AssetMap $MixedMaps
    (Get-TauriExecutableInfo $MixedPath).CanExpand | Should -BeFalse
    { Expand-TauriExecutable $MixedPath -DestinationPath (Join-Path $TestDrive 'mixed') } | Should -Throw '*does not contain one uniformly encoded*'

    $Path = New-TestTauriExecutable -Name 'tauri-truncated.exe'
    $Info = Get-TauriExecutableInfo $Path
    $Entry = $Info.AssetDescriptors | Where-Object Name -EQ '/index.html'
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    try { $Stream.SetLength($Entry.DataOffset + $Entry.StoredSize - 1) } finally { $Stream.Dispose() }
    { Expand-TauriExecutable $Path -DestinationPath (Join-Path $TestDrive 'truncated') } | Should -Throw

    $LimitPath = New-TestTauriExecutable -Name 'tauri-limit.exe'
    { Expand-TauriExecutable $LimitPath -DestinationPath (Join-Path $TestDrive 'limit') -MaximumExpandedBytes 4 } | Should -Throw '*output limit*'
  }
}

Describe 'Tauri analyzer integration' {
  It 'adds Tauri evidence to a loose portable PE without adding an installer family' {
    $Path = New-TestTauriExecutable -Name 'tauri-analyzer.exe'
    $Analysis = Get-WinGetInstallerAnalysis -Path $Path

    $Analysis.PortableEvidence.TauriExecutableInfo.Framework | Should -Be 'Tauri'
    $Analysis.PortableEvidence.TauriExecutableInfo.AssetCount | Should -Be 2
    $Analysis.FamilyCandidates.Family | Should -Not -Contain 'Tauri'
  }

  It 'adds Tauri evidence to an extracted ZIP portable candidate' {
    $SourceDirectory = Join-Path $TestDrive 'tauri-zip-source'
    $null = New-Item -Path $SourceDirectory -ItemType Directory
    $ExecutablePath = New-TestTauriExecutable -Name 'tauri-zip-source.exe'
    Copy-Item -LiteralPath $ExecutablePath -Destination (Join-Path $SourceDirectory 'application.exe')
    $ArchivePath = Join-Path $TestDrive 'tauri-portable.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($SourceDirectory, $ArchivePath)

    $Analysis = Get-WinGetInstallerAnalysis -Path $ArchivePath
    $ArchiveEvidence = $Analysis.ParserResults | Where-Object { $_.Success -and $_.Result.Family -eq 'ZIP/archive' } | Select-Object -ExpandProperty Result -First 1
    $Candidate = $ArchiveEvidence.PortableCandidateEvidence | Where-Object RelativeFilePath -EQ 'application.exe' | Select-Object -First 1

    $Candidate.Evidence.TauriExecutableInfo.Framework | Should -Be 'Tauri'
    $Candidate.Evidence.TauriExecutableInfo.AssetCount | Should -Be 2
  }

  It 'loads the scanner repeatedly without duplicate type failures' {
    { Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\Tauri.psm1') -Force } | Should -Not -Throw
    { Import-Module (Join-Path $PSScriptRoot '..\Libraries\Installers\Tauri.psm1') -Force } | Should -Not -Throw
  }
}

Describe 'Tauri real executable regressions' -Tag 'RealFixture' {
  It 'does not classify a cached Tauri NSIS wrapper as the application executable' {
    $Path = Join-Path $Script:TauriFixtureDirectory 'Downloads\ChatWise_0.9.76_x64-setup.exe'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent ChatWise NSIS fixture is not cached.'
      return
    }
    Test-TauriExecutable -Path $Path | Should -BeFalse
  }

  It 'parses the cached Clash Verge 1.7.7 x86 portable application when available' {
    $Path = Join-Path $Script:TauriFixtureDirectory 'Clash.Verge_1.7.7_x86_portable\Clash Verge.exe'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent Clash Verge x86 fixture is not cached.'
      return
    }
    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.Architecture | Should -Be 'x86'
    $Info.AssetCompression | Should -Be 'Brotli'
    $Info.AssetCount | Should -BeGreaterThan 50
    $Info.EntryPageCandidates | Should -Contain '/index.html'
  }

  It 'parses persistent portable applications across Tauri generations and architectures' -ForEach @(
    @{ Name = 'Clash.Verge_1.7.7_x64.exe'; Architecture = 'x64'; MinimumAssets = 90; ExpectedBundle = $null }
    @{ Name = 'Clash.Verge_1.7.7_arm64.exe'; Architecture = 'arm64'; MinimumAssets = 90; ExpectedBundle = $null }
    @{ Name = 'Clash.Verge_2.5.2_x64.exe'; Architecture = 'x64'; MinimumAssets = 290; ExpectedBundle = 'NSIS' }
    @{ Name = 'Readest_0.11.20_x64.exe'; Architecture = 'x64'; MinimumAssets = 600; ExpectedBundle = 'Unknown' }
    @{ Name = 'Readest_0.11.20_arm64.exe'; Architecture = 'arm64'; MinimumAssets = 600; ExpectedBundle = 'Unknown' }
    @{ Name = 'Yaak_2026.4.0_x64.exe'; Architecture = 'x64'; MinimumAssets = 280; ExpectedBundle = 'NSIS' }
    @{ Name = 'ChatWise_0.9.76_x64.exe'; Architecture = 'x64'; MinimumAssets = 190; ExpectedBundle = $null }
    @{ Name = 'Antigravity.Tools_3.3.15_x64.exe'; Architecture = 'x64'; MinimumAssets = 6; ExpectedBundle = $null }
  ) {
    $Path = Join-Path $Script:TauriFixtureDirectory "Applications\$Name"
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because "The persistent Tauri fixture '$Name' is not cached."
      return
    }
    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.Architecture | Should -Be $Architecture
    $Info.AssetCount | Should -BeGreaterOrEqual $MinimumAssets
    $Info.AssetCompression | Should -Be 'Brotli'
    $Info.CanExpand | Should -BeTrue
    $Info.BundleType | Should -Be $ExpectedBundle
  }
}
