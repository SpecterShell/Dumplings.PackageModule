. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  . (Join-Path $Script:DumplingsModuleRoot 'Index.ps1')

  $Script:TauriSyntheticDirectory = Join-Path $TestDrive 'Synthetic'
  $null = New-Item -Path $Script:TauriSyntheticDirectory -ItemType Directory -Force

  function Get-TauriRealApplicationFixture {
    param([Parameter(Mandatory)][string]$Name)

    $SourceName = switch ($Name) {
      'Clash.Verge_1.7.7_x86.exe' { 'Clash.Verge_1.7.7_x86_portable.zip' }
      'Clash.Verge_1.7.7_x64.exe' { 'Clash.Verge_1.7.7_x64_portable.zip' }
      'Clash.Verge_1.7.7_arm64.exe' { 'Clash.Verge_1.7.7_arm64_portable.zip' }
      'Clash.Verge_2.5.2_x64.exe' { 'Clash.Verge_2.5.2_x64-setup.exe' }
      'Readest_0.9.100_x64.exe' { 'Readest_0.9.100_x64-portable.exe' }
      'Readest_0.11.20_x64.exe' { 'Readest_0.11.20_x64-portable.exe' }
      'Readest_0.11.20_arm64.exe' { 'Readest_0.11.20_arm64-portable.exe' }
      'Yaak_2026.4.0_x64.exe' { 'Yaak_2026.4.0_x64-setup.exe' }
      'ChatWise_0.9.76_x64.exe' { 'ChatWise_0.9.76_x64-setup.exe' }
      'Antigravity.Tools_3.3.15_x64.exe' { 'Antigravity.Tools_3.3.15_x64-setup.exe' }
    }
    if (-not $SourceName) { throw "No source fixture is registered for '$Name'." }
    $Source = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $SourceName)
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return $null }
    if ($SourceName.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase)) {
      $Destination = Join-Path $TestDrive ([IO.Path]::GetFileNameWithoutExtension($SourceName))
      if (-not (Test-Path -LiteralPath $Destination)) { [IO.Compression.ZipFile]::ExtractToDirectory($Source, $Destination) }
      return Get-ChildItem -LiteralPath $Destination -Filter '*.exe' -File | Where-Object Name -EQ 'Clash Verge.exe' | Select-Object -ExpandProperty FullName -First 1
    }
    if ($SourceName -like '*portable.exe') { return $Source }
    $NestedName = switch -Wildcard ($SourceName) {
      'Clash.Verge*' { 'clash-verge.exe' }
      'Yaak*' { 'yaak-app-client.exe' }
      'ChatWise*' { 'chatwise.exe' }
      'Antigravity*' { 'antigravity_tools.exe' }
    }
    $Destination = Join-Path $TestDrive ([IO.Path]::GetFileNameWithoutExtension($SourceName))
    $Existing = Get-ChildItem -LiteralPath $Destination -Filter $NestedName -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($Existing) { return $Existing }
    $Extracted = @(Expand-NSISInstaller -Path $Source -DestinationPath $Destination -Name $NestedName -CollisionAction Rename)
    return $Extracted[0].FullName
  }

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
      [ValidateSet('Brotli', 'None', 'CspHash')][string]$Compression = 'Brotli'
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
      [ValidateSet('NSS', 'MSI', 'UNK')][string]$LegacyBundleType,
      [ValidateSet('NSS', 'MSI', 'UNK')][string]$LongBundleType,
      [ValidateLength(1, 8)][string]$DataSectionName = '.data',
      [ValidateRange(0, 4096)][int]$MapGap = 0x80,
      [string[]]$Marker = @('tauri://localhost', '__TAURI_INTERNALS__', '__TAURI_BUNDLE_TYPE_VAR_NSS')
    )

    if ($LegacyBundleType -and $LongBundleType) { throw 'Synthetic fixtures cannot combine legacy and long bundle references.' }

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
    Write-TestUInt16 ($PeOffset + 6) $(if ($LegacyBundleType -or $LongBundleType) { 2 } else { 1 })
    Write-TestUInt16 ($PeOffset + 20) $OptionalHeaderSize
    $Characteristics = if ($Dll) { [uint16]0x2102 } else { [uint16]0x0102 }
    $OptionalHeaderMagic = if ($PE32) { [uint16]0x010B } else { [uint16]0x020B }
    Write-TestUInt16 ($PeOffset + 22) $Characteristics
    Write-TestUInt16 $OptionalHeaderOffset $OptionalHeaderMagic
    if ($PE32) { Write-TestUInt32 ($OptionalHeaderOffset + 28) ([uint32]$ImageBase) }
    else { Write-TestUInt64 ($OptionalHeaderOffset + 24) $ImageBase }
    Write-TestUInt32 ($OptionalHeaderOffset + 56) $(if ($LegacyBundleType -or $LongBundleType) { 0x62000 } else { 0x61000 })
    Write-TestUInt32 ($OptionalHeaderOffset + 60) 0x200
    Write-TestUInt16 ($OptionalHeaderOffset + 68) 2
    $NumberOfRvaAndSizesOffset = $OptionalHeaderOffset + $(if ($PE32) { 92 } else { 108 })
    Write-TestUInt32 $NumberOfRvaAndSizesOffset 16

    Write-TestBytes $SectionOffset ([Text.Encoding]::ASCII.GetBytes('.rdata'))
    $RdataSize = if ($LegacyBundleType -or $LongBundleType) { 0x5FC00 } else { 0x5FE00 }
    Write-TestUInt32 ($SectionOffset + 8) $RdataSize
    Write-TestUInt32 ($SectionOffset + 12) 0x1000
    Write-TestUInt32 ($SectionOffset + 16) $RdataSize
    Write-TestUInt32 ($SectionOffset + 20) 0x200
    Write-TestUInt32 ($SectionOffset + 36) 0x40000040

    if ($LegacyBundleType) {
      $LegacySectionOffset = $SectionOffset + 40
      Write-TestBytes $LegacySectionOffset ([Text.Encoding]::ASCII.GetBytes('.taubndl'))
      Write-TestUInt32 ($LegacySectionOffset + 8) ($PointerSize * 2)
      Write-TestUInt32 ($LegacySectionOffset + 12) 0x61000
      Write-TestUInt32 ($LegacySectionOffset + 16) 0x200
      Write-TestUInt32 ($LegacySectionOffset + 20) 0x5FE00
      Write-TestUInt32 ($LegacySectionOffset + 36) 0x40000040

      $LegacyValueOffset = 0x17F00
      Write-TestBytes $LegacyValueOffset ([Text.Encoding]::ASCII.GetBytes($LegacyBundleType))
      Write-TestPointer 0x5FE00 (Convert-TestOffsetToVa $LegacyValueOffset)
      Write-TestPointer (0x5FE00 + $PointerSize) 3
    } elseif ($LongBundleType) {
      $DataSectionOffset = $SectionOffset + 40
      Write-TestBytes $DataSectionOffset ([Text.Encoding]::ASCII.GetBytes($DataSectionName))
      Write-TestUInt32 ($DataSectionOffset + 8) ($PointerSize * 2)
      Write-TestUInt32 ($DataSectionOffset + 12) 0x61000
      Write-TestUInt32 ($DataSectionOffset + 16) 0x200
      Write-TestUInt32 ($DataSectionOffset + 20) 0x5FE00
      Write-TestUInt32 ($DataSectionOffset + 36) ([uint32]0xC0000040L)
    }

    $RecordOffset = 0x400
    $NameOffset = 0x20000
    $DataOffset = 0x30000
    foreach ($Map in $AssetMap) {
      foreach ($Asset in $Map.Assets) {
        $NameBytes = [Text.Encoding]::UTF8.GetBytes([string]$Asset.Name)
        Write-TestBytes $NameOffset $NameBytes
        if ($Asset.Compression -eq 'CspHash') {
          $HashBytes = [byte[]]$Asset.Content
          $HashOffset = $DataOffset + ($PointerSize * 3)
          Write-TestPointer $DataOffset 0
          Write-TestPointer ($DataOffset + $PointerSize) (Convert-TestOffsetToVa $HashOffset)
          Write-TestPointer ($DataOffset + ($PointerSize * 2)) $HashBytes.Length
          Write-TestBytes $HashOffset $HashBytes
          $StoredLength = 1
          $PayloadPointer = Convert-TestOffsetToVa $DataOffset
          $DataLength = ($PointerSize * 3) + $HashBytes.Length
        } else {
          $StoredBytes = if ($Asset.Compression -eq 'Brotli') { Compress-TestTauriBrotli -Bytes $Asset.Content } else { [byte[]]$Asset.Content }
          if ($StoredBytes.Length -gt 0) { Write-TestBytes $DataOffset $StoredBytes }
          $StoredLength = $StoredBytes.Length
          # Empty Rust slices use a dangling pointer and never dereference it.
          $PayloadPointer = if ($StoredBytes.Length -eq 0) { [uint64]1 } else { Convert-TestOffsetToVa $DataOffset }
          $DataLength = $StoredBytes.Length
        }
        Write-TestPointer $RecordOffset (Convert-TestOffsetToVa $NameOffset)
        Write-TestPointer ($RecordOffset + $PointerSize) $NameBytes.Length
        Write-TestPointer ($RecordOffset + ($PointerSize * 2)) $PayloadPointer
        Write-TestPointer ($RecordOffset + ($PointerSize * 3)) $StoredLength
        $RecordOffset += $RecordSize
        $NameOffset += $NameBytes.Length + 16
        $DataOffset += $DataLength + 16
      }
      $RecordOffset += $MapGap
    }

    $MarkerOffset = 0x18000
    $MarkerOffsets = @{}
    foreach ($Value in $Marker) {
      $MarkerBytes = [Text.Encoding]::ASCII.GetBytes($Value)
      Write-TestBytes $MarkerOffset $MarkerBytes
      $MarkerOffsets[$Value] = $MarkerOffset
      $MarkerOffset += $MarkerBytes.Length + 8
    }
    if ($LongBundleType) {
      $RuntimeToken = "__TAURI_BUNDLE_TYPE_VAR_$LongBundleType"
      if (-not $MarkerOffsets.ContainsKey($RuntimeToken)) { throw "The synthetic marker list does not contain '$RuntimeToken'." }
      Write-TestPointer 0x5FE00 (Convert-TestOffsetToVa $MarkerOffsets[$RuntimeToken])
      Write-TestPointer (0x5FE00 + $PointerSize) $RuntimeToken.Length
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
    ($Info.TauriMarkerEvidence | Where-Object Name -EQ 'AssetOrigin' | Select-Object -First 1).Format | Should -Be 'StringLiteral'
  }

  It 'recognizes a Tauri 1.x executable with a custom asset provider from legacy runtime markers' {
    $Path = New-TestTauriExecutable -Name 'tauri-v1-custom-provider.exe' -AssetMap @() `
      -Marker @('__TAURI_PATTERN__', '__TAURI_METADATA__')

    Test-TauriExecutable -Path $Path | Should -BeTrue
    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.AssetCount | Should -Be 0
    $Info.TauriMarkerEvidence.Name | Should -Contain 'LegacyPattern'
    $Info.TauriMarkerEvidence.Name | Should -Contain 'LegacyMetadata'
    $Info.BundleType | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'EmbeddedAssets'
    $Info.UnresolvedFields | Should -Contain 'BundleType'
    $Info.Diagnostics.Id | Should -Contain 'Tauri.AssetMap.NotRecovered'
  }

  It 'leaves conflicting long bundle tokens unresolved' -ForEach @(
    @{ Name = 'tauri-x64.exe'; Machine = [uint16]0x8664; Architecture = 'x64' }
    @{ Name = 'tauri-arm64.exe'; Machine = [uint16]0xAA64; Architecture = 'arm64' }
  ) {
    $Path = New-TestTauriExecutable -Name $Name -Machine $Machine -Marker @(
      '__TAURI_BUNDLE_TYPE_VAR_NSS', '__TAURI_BUNDLE_TYPE_VAR_MSI', 'tauri://localhost', '__TAURI_INTERNALS__')
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.Architecture | Should -Be $Architecture
    $Info.ParserVersionInfo.RecordWidth | Should -Be 32
    $Info.AssetCompression | Should -Be 'Brotli'
    $Info.BundleType | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'BundleType'
    $Diagnostic = $Info.Diagnostics | Where-Object Id -EQ 'Tauri.BundleType.Conflict'
    $Diagnostic.Kind | Should -Be 'Ambiguous'
    $Diagnostic.AffectedFields | Should -Contain 'BundleType'
    $Diagnostic.Message | Should -Match 'conflicting Tauri bundle tags'
  }

  It 'uses the long token referenced by the mutable runtime string' -ForEach @(
    @{ Name = 'tauri-runtime-bundle-reference-x64.exe'; Machine = 0x8664; IsPE32 = $false }
    @{ Name = 'tauri-runtime-bundle-reference-x86.exe'; Machine = 0x014C; IsPE32 = $true }
  ) {
    $Arguments = @{ Name = $Name; Machine = $Machine; LongBundleType = 'MSI'; Marker = @('tauri://localhost', '__TAURI_INTERNALS__', '__TAURI_BUNDLE_TYPE_VAR_NSS', '__TAURI_BUNDLE_TYPE_VAR_MSI') }
    if ($IsPE32) { $Arguments.PE32 = $true }
    $Path = New-TestTauriExecutable @Arguments
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.BundleType | Should -Be 'MSI'
    $Info.BundleTypeMarker.Format | Should -Be 'LongToken'
    $Info.BundleTypeMarker.ReferenceOffset | Should -Be 0x5FE00
    $Info.BundleTypeMarker.IsRuntimeValue | Should -BeTrue
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.BundleType.Conflict'
  }

  It 'resolves a runtime token beyond the bounded marker catalog' {
    $Markers = @('tauri://localhost', '__TAURI_INTERNALS__') + @(1..33 | ForEach-Object { '__TAURI_BUNDLE_TYPE_VAR_MSI' })
    $Path = New-TestTauriExecutable -Name 'tauri-runtime-bundle-after-cap.exe' -LongBundleType MSI -Marker $Markers
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.BundleType | Should -Be 'MSI'
    $Info.BundleTypeEvidenceConfidence | Should -Be 'high'
    $Info.BundleTypeMarker.IsRuntimeValue | Should -BeTrue
    $Info.Diagnostics.Id | Should -Contain 'Tauri.MarkerEvidence.Truncated'
  }

  It 'finds the mutable runtime string in a custom writable data section' {
    $Path = New-TestTauriExecutable -Name 'tauri-custom-data-section.exe' -LongBundleType NSS -DataSectionName '.tdata' `
      -Marker @('tauri://localhost', '__TAURI_INTERNALS__', '__TAURI_BUNDLE_TYPE_VAR_NSS')
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.BundleType | Should -Be 'NSIS'
    $Info.BundleTypeEvidenceConfidence | Should -Be 'high'
    $Info.BundleTypeMarker.ReferenceOffset | Should -Be 0x5FE00
  }

  It 'labels the unique-token bundle fallback as non-authoritative' {
    $Path = New-TestTauriExecutable -Name 'tauri-unique-token-fallback.exe' `
      -Marker @('tauri://localhost', '__TAURI_INTERNALS__', '__TAURI_BUNDLE_TYPE_VAR_NSS')
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.BundleType | Should -Be 'NSIS'
    $Info.BundleTypeEvidenceConfidence | Should -Be 'medium'
    $Info.Diagnostics.Id | Should -Contain 'Tauri.BundleType.UniqueTokenFallback'
  }

  It 'reads legacy .taubndl fat pointers for PE32 and PE32+' -ForEach @(
    @{ Name = 'tauri-legacy-x86.exe'; Machine = [uint16]0x014C; PE32 = $true; Tag = 'NSS'; BundleType = 'NSIS'; IsResolved = $true }
    @{ Name = 'tauri-legacy-x64.exe'; Machine = [uint16]0x8664; PE32 = $false; Tag = 'MSI'; BundleType = 'MSI'; IsResolved = $true }
    @{ Name = 'tauri-legacy-unknown.exe'; Machine = [uint16]0x8664; PE32 = $false; Tag = 'UNK'; BundleType = 'Unknown'; IsResolved = $false }
  ) {
    $Path = New-TestTauriExecutable -Name $Name -Machine $Machine -PE32:$PE32 -LegacyBundleType $Tag `
      -Marker @('tauri://localhost', '__TAURI_INTERNALS__')
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.BundleType | Should -Be $BundleType
    $Info.BundleTypeMarker.Format | Should -Be 'LegacySection'
    $Info.BundleTypeMarker.Value | Should -Be $Tag
    ($Info.UnresolvedFields -contains 'BundleType') | Should -Be (-not $IsResolved)
  }

  It 'reports malformed legacy bundle sections without guessing the type' {
    $Path = New-TestTauriExecutable -Name 'tauri-invalid-legacy.exe' -LegacyBundleType NSS `
      -Marker @('tauri://localhost', '__TAURI_INTERNALS__')
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    try {
      $Stream.Position = 0x5FE00
      $Stream.Write([BitConverter]::GetBytes([uint64]::MaxValue))
    } finally { $Stream.Dispose() }

    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.BundleType | Should -BeNullOrEmpty
    $Diagnostic = $Info.Diagnostics | Where-Object Id -EQ 'Tauri.BundleType.InvalidLegacySection'
    $Diagnostic.AffectedFields | Should -Contain 'BundleType'
    $Diagnostic.Message | Should -Match 'does not contain a valid pointer-sized string record'
  }

  It 'catalogs the HTML CSP hash map separately from extractable assets' {
    $Maps = @(
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>app</html>')))
          (New-TestTauriAsset -Name '/app.js' -Content ([Text.Encoding]::UTF8.GetBytes('app')))
        )
      }
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::ASCII.GetBytes("'sha256-Wjjrs6qinmnr+tOry8x8PPwI77eGpUFR3EEGZktjJNs='")) -Compression CspHash)
          (New-TestTauriAsset -Name '/other.html' -Content ([Text.Encoding]::ASCII.GetBytes("'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='")) -Compression CspHash)
        )
      }
    )
    $Info = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-csp-map.exe' -AssetMap $Maps)

    $Info.AssetMapCount | Should -Be 1
    $Info.AssetCount | Should -Be 2
    $Info.AuxiliaryMapCount | Should -Be 1
    $Info.AuxiliaryMaps[0].Type | Should -Be 'HtmlCspHashMap'
    $Info.AuxiliaryMaps[0].HashCount | Should -Be 2
    $Info.AuxiliaryMaps[0].Directive | Should -Be 'script-src'
    $Info.ValidationWork.CspHashEntriesExamined | Should -Be 2
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.AssetMap.Unvalidated'
  }

  It 'separates an adjacent empty Tauri 1.x CSP map from the compressed asset map' {
    $Maps = @(
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>Tauri 1.x</html>')))
        )
      }
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([byte[]]::new(0)) -Compression None)
        )
      }
    )
    $Path = New-TestTauriExecutable -Name 'tauri-v1-adjacent-empty-csp.exe' -AssetMap $Maps -MapGap 0 `
      -Marker @('tauri://localhost', '__TAURI_PATTERN__', '__TAURI_METADATA__')
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.AssetCount | Should -Be 1
    $Info.AssetCompression | Should -Be 'Brotli'
    $Info.AuxiliaryMapCount | Should -Be 1
    $Info.AuxiliaryMaps[0].HashCount | Should -Be 0
    $Info.CanExpand | Should -BeTrue
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.AssetMap.MixedCompression'
  }

  It 'validates adjacent Tauri 1.x CSP maps containing empty and non-empty slices' {
    $Maps = @(
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>one</html>')))
          (New-TestTauriAsset -Name '/other.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>two</html>')))
        )
      }
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([byte[]]::new(0)) -Compression None)
          (New-TestTauriAsset -Name '/other.html' -Content ([Text.Encoding]::ASCII.GetBytes("'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='")) -Compression CspHash)
        )
      }
    )
    $Info = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-v1-adjacent-mixed-csp.exe' `
        -AssetMap $Maps -MapGap 0 -Marker @('tauri://localhost', '__TAURI_PATTERN__', '__TAURI_METADATA__'))

    $Info.AssetCount | Should -Be 2
    $Info.AuxiliaryMapCount | Should -Be 1
    $Info.AuxiliaryMaps[0].HashCount | Should -Be 1
    $Info.ValidationWork.CspHashEntriesExamined | Should -Be 1
    $Info.CanExpand | Should -BeTrue
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.AssetMap.MixedCompression'
  }

  It 'stops CSP enum validation at the cumulative work limit' {
    $Maps = @([pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::ASCII.GetBytes("'sha256-Wjjrs6qinmnr+tOry8x8PPwI77eGpUFR3EEGZktjJNs='")) -Compression CspHash)
          (New-TestTauriAsset -Name '/other.html' -Content ([Text.Encoding]::ASCII.GetBytes("'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='")) -Compression CspHash)
        )
      })
    $Path = New-TestTauriExecutable -Name 'tauri-csp-work-limit.exe' -AssetMap $Maps
    $TauriModule = Get-Module Tauri
    $OriginalLimit = & $TauriModule { $Script:TauriMaximumCspHashValidationEntries }
    try {
      & $TauriModule { param($Value) $Script:TauriMaximumCspHashValidationEntries = $Value } 1
      { Get-TauriExecutableInfo -Path $Path } | Should -Throw '*CSP hash validation exceeds*parser work limit*'
    } finally {
      & $TauriModule { param($Value) $Script:TauriMaximumCspHashValidationEntries = $Value } $OriginalLimit
    }
  }

  It 'does not hide malformed HTML-only runs as CSP hash maps' {
    $Maps = @(
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>app</html>')))
        )
      }
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([byte[]](0xFF, 0xFF, 0xFF, 0xFF)) -Compression None)
        )
      }
    )
    $Info = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-csp-near-miss.exe' -AssetMap $Maps)

    $Info.AuxiliaryMapCount | Should -Be 0
    $Info.CanExpand | Should -BeTrue
    $Info.Diagnostics.Id | Should -Contain 'Tauri.AssetMap.Unvalidated'
  }

  It 'validates PE32 CSP hash slices using the 12-byte Rust enum layout' {
    $Maps = @(
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>app</html>')))
        )
      }
      [pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::ASCII.GetBytes("'sha256-Wjjrs6qinmnr+tOry8x8PPwI77eGpUFR3EEGZktjJNs='")) -Compression CspHash)
        )
      }
    )
    $Info = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-x86-csp-map.exe' -Machine 0x014C -PE32 -AssetMap $Maps)

    $Info.AssetCount | Should -Be 1
    $Info.AuxiliaryMaps[0].HashCount | Should -Be 1
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.AssetMap.Unvalidated'
  }

  It 'keeps Test and Get consistent for one non-index raw asset' {
    $Maps = @([pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/custom.svg' -Content ([Text.Encoding]::UTF8.GetBytes('<svg xmlns="http://www.w3.org/2000/svg"></svg>')) -Compression None)
        )
      })
    $Path = New-TestTauriExecutable -Name 'tauri-single-raw.exe' -AssetMap $Maps

    Test-TauriExecutable -Path $Path | Should -BeTrue
    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.AssetCount | Should -Be 1
    $Info.AssetDescriptors[0].Name | Should -Be '/custom.svg'
    $Info.CanExpand | Should -BeTrue
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

  It 'measures a shared payload range once while retaining logical asset sizes' {
    $Content = [byte[]](1..12)
    $Maps = @([pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content $Content)
          (New-TestTauriAsset -Name '/copy.html' -Content $Content)
        )
      })
    $Path = New-TestTauriExecutable -Name 'tauri-shared-payload.exe' -AssetMap $Maps
    $Stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    try {
      $Pointer = [byte[]]::new(8)
      $Stream.Position = 0x410
      $Stream.ReadExactly($Pointer)
      $Stream.Position = 0x430
      $Stream.Write($Pointer)
    } finally { $Stream.Dispose() }

    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.ValidationWork.UniquePayloadCount | Should -Be 1
    $Info.ValidationWork.ExpandedBytesDecoded | Should -Be 12
    $Info.TotalExpandedBytes | Should -Be 24
  }

  It 'reports marker-only custom providers without claiming expandable assets' {
    $Info = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-marker-only.exe' -AssetMap @())

    $Info.DetectionConfidence | Should -Be 'medium'
    $Info.CanExpand | Should -BeFalse
    $Info.UnresolvedFields | Should -Contain 'EmbeddedAssets'
    $Info.Diagnostics.Id | Should -Contain 'Tauri.AssetMap.NotRecovered'
    ($Info.Diagnostics | Where-Object Id -EQ 'Tauri.AssetMap.NotRecovered').AffectedFields | Should -Contain 'EmbeddedAssets'
    ($Info.Diagnostics | Where-Object Id -EQ 'Tauri.AssetMap.NotRecovered').Message | Should -Match 'custom or URL-backed asset provider'
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
    $Info.Diagnostics.Id | Should -Contain 'Tauri.IdentifierCandidates.NonAuthoritative'
  }

  It 'scans a record across the managed block boundary' {
    $Bytes = [byte[]]::new(1048640)
    $ImageBase = [uint64]0x140000000
    $VirtualAddress = [uint32]0x1000
    $NameOffset = 0x100
    $DataOffset = 0x200
    $RecordOffset = 1048568
    $NameBytes = [Text.Encoding]::UTF8.GetBytes('/index.html')
    $DataBytes = [Text.Encoding]::UTF8.GetBytes('<html>boundary</html>')
    $NameBytes.CopyTo($Bytes, $NameOffset)
    $DataBytes.CopyTo($Bytes, $DataOffset)
    [BitConverter]::GetBytes($ImageBase + $VirtualAddress + $NameOffset).CopyTo($Bytes, $RecordOffset)
    [BitConverter]::GetBytes([uint64]$NameBytes.Length).CopyTo($Bytes, $RecordOffset + 8)
    [BitConverter]::GetBytes($ImageBase + $VirtualAddress + $DataOffset).CopyTo($Bytes, $RecordOffset + 16)
    [BitConverter]::GetBytes([uint64]$DataBytes.Length).CopyTo($Bytes, $RecordOffset + 24)
    $Section = [Dumplings.Tauri.TauriPeSection]@{ Name = '.rdata'; VirtualAddress = $VirtualAddress; RawOffset = 0; RawSize = $Bytes.Length }
    $Stream = [IO.MemoryStream]::new($Bytes, $false)
    try {
      $Records = [Dumplings.Tauri.TauriExecutableScanner]::FindAssetRecords(
        $Stream, $ImageBase, 8, [Dumplings.Tauri.TauriPeSection[]]@($Section), 4096, 1048576, 10, $Bytes.Length, $Bytes.Length)
      $Records | Should -HaveCount 1
      $Records[0].HeaderOffset | Should -Be $RecordOffset
      $Records[0].Name | Should -Be '/index.html'
    } finally { $Stream.Dispose() }
  }

  It 'enforces managed scan budgets and restores caller stream positions' {
    $Bytes = [byte[]]::new(128)
    $Section = [Dumplings.Tauri.TauriPeSection]@{ Name = '.rdata'; VirtualAddress = 0; RawOffset = 0; RawSize = $Bytes.Length }
    $Sections = [Dumplings.Tauri.TauriPeSection[]]@($Section)
    $Stream = [IO.MemoryStream]::new($Bytes, $false)
    try {
      $Stream.Position = 7
      { [Dumplings.Tauri.TauriExecutableScanner]::FindAssetRecords($Stream, 0, 8, $Sections, 4096, 1048576, 10, 64, 128) } | Should -Throw '*scan exceeds*'
      $Stream.Position | Should -Be 7
      { [Dumplings.Tauri.TauriExecutableScanner]::FindIdentifierCandidates($Stream, $Sections, 10, 256, 64) } | Should -Throw '*scan exceeds*'
      $Stream.Position | Should -Be 7
    } finally { $Stream.Dispose() }
  }

  It 'enforces the asset-record candidate work limit' {
    $Bytes = [byte[]]::new(128)
    $Section = [Dumplings.Tauri.TauriPeSection]@{ Name = '.rdata'; VirtualAddress = 0; RawOffset = 0; RawSize = $Bytes.Length }
    $Stream = [IO.MemoryStream]::new($Bytes, $false)
    try {
      $Stream.Position = 9
      { [Dumplings.Tauri.TauriExecutableScanner]::FindAssetRecords(
          $Stream, 0, 8, [Dumplings.Tauri.TauriPeSection[]]@($Section), 4096, 1048576, 10, 128, 2) } | Should -Throw '*candidate work limit*'
      $Stream.Position | Should -Be 9
    } finally { $Stream.Dispose() }
  }

  It 'stops identifier scanning when the candidate limit is reached' {
    $Bytes = [byte[]]::new(64)
    [Text.Encoding]::ASCII.GetBytes("com.example.app`0").CopyTo($Bytes, 0)
    $Sections = [Dumplings.Tauri.TauriPeSection[]]@(
      [Dumplings.Tauri.TauriPeSection]@{ Name = '.rdata'; VirtualAddress = 0; RawOffset = 0; RawSize = 64 }
      [Dumplings.Tauri.TauriPeSection]@{ Name = '.rdata'; VirtualAddress = 0x1000; RawOffset = 4096; RawSize = 64 }
    )
    $Stream = [IO.MemoryStream]::new($Bytes, $false)
    try {
      $Candidates = [Dumplings.Tauri.TauriExecutableScanner]::FindIdentifierCandidates($Stream, $Sections, 1, 256, 128)
      $Candidates | Should -HaveCount 1
      $Candidates[0].Value | Should -Be 'com.example.app'
    } finally { $Stream.Dispose() }
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
    ($Info.Diagnostics | Where-Object Id -EQ 'Tauri.AssetMap.NotRecovered').Message | Should -Match 'custom or URL-backed asset provider'
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
    $UnsafeInfo = Get-TauriExecutableInfo -Path (New-TestTauriExecutable -Name 'tauri-traversal.exe' -AssetMap $UnsafeMaps)
    $UnsafeInfo.CanExpand | Should -BeFalse
    $UnsafeInfo.Diagnostics.Id | Should -Contain 'Tauri.AssetMap.UnsafePath'

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

  It 'stops Brotli validation at the cumulative work limit' {
    $Maps = @([pscustomobject]@{ Assets = @(
          (New-TestTauriAsset -Name '/index.html' -Content ([byte[]](1..12)))
          (New-TestTauriAsset -Name '/app.js' -Content ([byte[]](13..24)))
        )
      })
    $Path = New-TestTauriExecutable -Name 'tauri-brotli-work-limit.exe' -AssetMap $Maps
    $TauriModule = Get-Module Tauri
    $OriginalLimit = & $TauriModule { $Script:TauriMaximumMeasuredExpandedBytes }
    try {
      & $TauriModule { param($Value) $Script:TauriMaximumMeasuredExpandedBytes = $Value } 20
      { Get-TauriExecutableInfo -Path $Path } | Should -Throw '*cumulative parser work limit*'
    } finally {
      & $TauriModule { param($Value) $Script:TauriMaximumMeasuredExpandedBytes = $Value } $OriginalLimit
    }
  }

  It 'bounds cumulative Brotli input in the fast detection path' {
    $Invalid = [byte[]](0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
    $Maps = @(
      [pscustomobject]@{ Assets = @((New-TestTauriAsset -Name '/index.html' -Content $Invalid -Compression None)) }
      [pscustomobject]@{ Assets = @((New-TestTauriAsset -Name '/index.html' -Content $Invalid -Compression None)) }
      [pscustomobject]@{ Assets = @((New-TestTauriAsset -Name '/index.html' -Content ([Text.Encoding]::UTF8.GetBytes('<html>valid</html>')))) }
    )
    $Path = New-TestTauriExecutable -Name 'tauri-test-work-limit.exe' -AssetMap $Maps
    $TauriModule = Get-Module Tauri
    $OriginalLimit = & $TauriModule { $Script:TauriMaximumMeasuredStoredBytes }
    try {
      & $TauriModule { param($Value) $Script:TauriMaximumMeasuredStoredBytes = $Value } 20
      Test-TauriExecutable -Path $Path | Should -BeFalse
    } finally {
      & $TauriModule { param($Value) $Script:TauriMaximumMeasuredStoredBytes = $Value } $OriginalLimit
    }
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

  It 'gates Tauri 1.x custom-provider executables on the legacy pattern marker' {
    $Path = New-TestTauriExecutable -Name 'tauri-v1-analyzer.exe' -AssetMap @() `
      -Marker @('__TAURI_PATTERN__', '__TAURI_METADATA__')
    $Analysis = Get-WinGetInstallerAnalysis -Path $Path

    $Analysis.PortableEvidence.TauriExecutableInfo.Framework | Should -Be 'Tauri'
    $Analysis.PortableEvidence.TauriExecutableInfo.AssetCount | Should -Be 0
    $Analysis.PortableEvidence.TauriExecutableInfo.TauriMarkerEvidence.Name | Should -Contain 'LegacyPattern'
    $Analysis.FamilyCandidates.Family | Should -Not -Contain 'Tauri'
  }

  It 'preserves a marker-positive Tauri parser failure as a diagnostic' {
    $Path = New-TestTauriExecutable -Name 'tauri-analyzer-parser-failure.exe'
    Mock Get-TauriExecutableInfo -ModuleName InstallerAnalyzer { throw 'synthetic Tauri parser failure' }

    $Analysis = Get-WinGetInstallerAnalysis -Path $Path

    $Analysis.PortableEvidence.TauriExecutableInfo | Should -BeNullOrEmpty
    $Diagnostic = $Analysis.Diagnostics | Where-Object Id -EQ 'Tauri.ParserFailed'
    $Diagnostic.Message | Should -Be 'synthetic Tauri parser failure'
    $Diagnostic.Evidence.GateMarker | Should -Not -BeNullOrEmpty
  }

  It 'uses the legacy bundle section as the portable-analysis gate' {
    $Path = New-TestTauriExecutable -Name 'tauri-legacy-gate.exe' -LegacyBundleType MSI -Marker @()
    $Analysis = Get-WinGetInstallerAnalysis -Path $Path

    $Analysis.PortableEvidence.TauriExecutableInfo.Framework | Should -Be 'Tauri'
    $Analysis.PortableEvidence.TauriExecutableInfo.BundleType | Should -Be 'MSI'
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
    { Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\Tauri.psm1') -Force } | Should -Not -Throw
    { Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\Tauri.psm1') -Force } | Should -Not -Throw
  }
}

Describe 'Tauri real executable regressions' -Tag 'RealFixture', 'Network' {
  It 'does not classify a cached Tauri NSIS wrapper as the application executable' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'ChatWise_0.9.76_x64-setup.exe')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent ChatWise NSIS fixture is not cached.'
      return
    }
    Test-TauriExecutable -Path $Path | Should -BeFalse
  }

  It 'parses the cached Clash Verge 1.7.7 x86 portable application when available' {
    $Path = Get-TauriRealApplicationFixture -Name 'Clash.Verge_1.7.7_x86.exe'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent Clash Verge x86 fixture is not cached.'
      return
    }
    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.Architecture | Should -Be 'x86'
    $Info.AssetCompression | Should -Be 'Brotli'
    $Info.AssetCount | Should -BeGreaterThan 50
    $Info.EntryPageCandidates | Should -Contain '/index.html'
    $Info.TauriMarkerEvidence.Name | Should -Contain 'LegacyPattern'
    $Info.TauriMarkerEvidence.Name | Should -Contain 'LegacyMetadata'
    $Info.TauriMarkerEvidence.Name | Should -Not -Contain 'Internals'
    $Info.BundleType | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'BundleType'
  }

  It 'reads the legacy NSIS bundle tag from a Tauri 2.9.5 portable application' {
    $Path = Get-TauriRealApplicationFixture -Name 'Readest_0.9.100_x64.exe'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent Readest 0.9.100 fixture is not cached.'
      return
    }
    $Info = Get-TauriExecutableInfo -Path $Path

    $Info.Architecture | Should -Be 'x64'
    $Info.AssetCount | Should -BeGreaterOrEqual 400
    $Info.AuxiliaryMapCount | Should -BeGreaterOrEqual 1
    $Info.BundleType | Should -Be 'NSIS'
    $Info.BundleTypeMarker.Format | Should -Be 'LegacySection'
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.AssetMap.Unvalidated'
  }

  It 'parses persistent portable applications across Tauri generations and architectures' -ForEach @(
    @{ Name = 'Clash.Verge_1.7.7_x64.exe'; Architecture = 'x64'; MinimumAssets = 90; ExpectedBundle = $null; ExpectedBundleFormat = $null }
    @{ Name = 'Clash.Verge_1.7.7_arm64.exe'; Architecture = 'arm64'; MinimumAssets = 90; ExpectedBundle = $null; ExpectedBundleFormat = $null }
    @{ Name = 'Clash.Verge_2.5.2_x64.exe'; Architecture = 'x64'; MinimumAssets = 290; ExpectedBundle = 'NSIS'; ExpectedBundleFormat = 'LongToken' }
    @{ Name = 'Readest_0.11.20_x64.exe'; Architecture = 'x64'; MinimumAssets = 600; ExpectedBundle = 'Unknown'; ExpectedBundleFormat = 'LongToken' }
    @{ Name = 'Readest_0.11.20_arm64.exe'; Architecture = 'arm64'; MinimumAssets = 600; ExpectedBundle = 'Unknown'; ExpectedBundleFormat = 'LongToken' }
    @{ Name = 'Yaak_2026.4.0_x64.exe'; Architecture = 'x64'; MinimumAssets = 280; ExpectedBundle = 'NSIS'; ExpectedBundleFormat = 'LongToken' }
    @{ Name = 'ChatWise_0.9.76_x64.exe'; Architecture = 'x64'; MinimumAssets = 190; ExpectedBundle = 'NSIS'; ExpectedBundleFormat = 'LegacySection' }
    @{ Name = 'Antigravity.Tools_3.3.15_x64.exe'; Architecture = 'x64'; MinimumAssets = 6; ExpectedBundle = 'NSIS'; ExpectedBundleFormat = 'LegacySection' }
  ) {
    $Path = Get-TauriRealApplicationFixture -Name $Name
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
    $Info.BundleTypeMarker.Format | Should -Be $ExpectedBundleFormat
  }
}

Describe 'Tauri controlled source-build regressions' -Tag 'RealFixture', 'SourceBuild' {
  It 'parses and extracts a Tauri 1.8.3 build with an adjacent empty CSP map' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Tauri\v1.8.3\x64\helloworld.exe'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The controlled Tauri 1.8.3 source-build fixture is not cached.'
      return
    }

    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash | Should -Be 'B6C99FDBA0209BB3FC12897A7FE57257EC240A1F9E544A9D1D6F8A0EB69EB2A9'
    $Info = Get-TauriExecutableInfo -Path $Path
    $Files = @(Expand-TauriExecutable -Path $Path -DestinationPath (Join-Path $TestDrive 'tauri-v1.8.3'))

    $Info.Architecture | Should -Be 'x64'
    $Info.AssetCount | Should -Be 1
    $Info.AssetCompression | Should -Be 'Brotli'
    $Info.AuxiliaryMapCount | Should -Be 1
    $Info.AuxiliaryMaps[0].HashCount | Should -Be 0
    $Info.TauriMarkerEvidence.Name | Should -Contain 'LegacyPattern'
    $Info.TauriMarkerEvidence.Name | Should -Contain 'LegacyMetadata'
    $Info.BundleType | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'BundleType'
    $Info.CanExpand | Should -BeTrue
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.AssetMap.MixedCompression'
    $Files | Should -HaveCount 1
    (Get-FileHash -LiteralPath $Files[0].FullName -Algorithm SHA256).Hash | Should -Be 'FA349DC28C1B9370C212A25336A7DF11D186EF573371397E9C79F2A7F00DF89D'
    Get-Content -LiteralPath $Files[0].FullName -Raw | Should -Match '<title>Welcome to Tauri!</title>'
  }

  It 'parses current PE32 and ARM64 source builds' -ForEach @(
    @{ RelativePath = 'Builders\Tauri\v2.11.5\x86\helloworld.exe'; Architecture = 'x86'; RecordWidth = 16; Hash = '85B0686C4A31CC9EC90C100A39F5C633A79CE431709050F1E8CFA6E2967088EA' }
    @{ RelativePath = 'Builders\Tauri\v2.11.5\arm64\helloworld.exe'; Architecture = 'arm64'; RecordWidth = 32; Hash = 'EC45E929665323014F1BFA3A0EDE76DE9028EB5BA969F0A848BBFBADD1543A82' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because "The controlled Tauri $Architecture source-build fixture is not cached."
      return
    }

    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash | Should -Be $Hash
    $Info = Get-TauriExecutableInfo -Path $Path
    $Info.Architecture | Should -Be $Architecture
    $Info.ParserVersionInfo.RecordWidth | Should -Be $RecordWidth
    $Info.AssetCount | Should -Be 1
    $Info.AuxiliaryMapCount | Should -Be 1
    $Info.AuxiliaryMaps[0].Type | Should -Be 'HtmlCspHashMap'
    $Info.AuxiliaryMaps[0].HashCount | Should -Be 1
    $Info.BundleType | Should -Be 'Unknown'
    $Info.BundleTypeEvidenceConfidence | Should -Be 'high'
    $Info.CanExpand | Should -BeTrue
  }

  It 'parses and extracts matching assets from Tauri 2.11.5 compressed and raw builds' {
    $CompressedPath = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Tauri\v2.11.5\compressed\helloworld.exe'
    $RawPath = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Tauri\v2.11.5\raw\helloworld.exe'
    if (-not (Test-Path -LiteralPath $CompressedPath -PathType Leaf) -or -not (Test-Path -LiteralPath $RawPath -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The controlled Tauri 2.11.5 source-build fixtures are not cached.'
      return
    }

    $CompressedInfo = Get-TauriExecutableInfo -Path $CompressedPath
    $RawInfo = Get-TauriExecutableInfo -Path $RawPath
    $CompressedFiles = @(Expand-TauriExecutable -Path $CompressedPath -DestinationPath (Join-Path $TestDrive 'compressed'))
    $RawFiles = @(Expand-TauriExecutable -Path $RawPath -DestinationPath (Join-Path $TestDrive 'raw'))

    Test-TauriExecutable -Path $CompressedPath | Should -BeTrue
    Test-TauriExecutable -Path $RawPath | Should -BeTrue
    $CompressedInfo.AssetCount | Should -Be 1
    $RawInfo.AssetCount | Should -Be 1
    $CompressedInfo.AuxiliaryMapCount | Should -Be 1
    $RawInfo.AuxiliaryMapCount | Should -Be 1
    $CompressedInfo.AssetCompression | Should -Be 'Brotli'
    $RawInfo.AssetCompression | Should -Be 'None'
    $CompressedInfo.TotalStoredBytes | Should -BeLessThan $RawInfo.TotalStoredBytes
    $CompressedInfo.TotalExpandedBytes | Should -Be $RawInfo.TotalExpandedBytes
    $CompressedFiles | Should -HaveCount 1
    $RawFiles | Should -HaveCount 1
    (Get-FileHash -LiteralPath $CompressedFiles[0].FullName -Algorithm SHA256).Hash | Should -Be (Get-FileHash -LiteralPath $RawFiles[0].FullName -Algorithm SHA256).Hash
  }

  It 'reads the MSI bundle type from the builder-packaged application' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Tauri\v2.11.5\msi\bench_helloworld.exe'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The controlled Tauri 2.11.5 MSI application fixture is not cached.'
      return
    }

    $Info = Get-TauriExecutableInfo -Path $Path
    Test-TauriExecutable -Path $Path | Should -BeTrue
    $Info.BundleType | Should -Be 'MSI'
    $Info.BundleTypeMarker.Format | Should -Be 'LongToken'
    $Info.BundleTypeMarker.IsRuntimeValue | Should -BeTrue
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.BundleType.Conflict'
  }

  It 'reads the NSIS bundle type from the builder-packaged application and rejects its wrapper' {
    $ApplicationPath = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Tauri\v2.11.5\nsis\bench_helloworld.exe'
    $WrapperPath = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Tauri\v2.11.5\nsis\Dumplings Tauri Audit_2.11.5_x64-setup.exe'
    if (-not (Test-Path -LiteralPath $ApplicationPath -PathType Leaf) -or -not (Test-Path -LiteralPath $WrapperPath -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The controlled Tauri 2.11.5 NSIS fixtures are not cached.'
      return
    }

    (Get-FileHash -LiteralPath $ApplicationPath -Algorithm SHA256).Hash | Should -Be '94EA6607924499732632CEE4C1756CD59452F7C06B38496BA9AB18B759029451'
    (Get-FileHash -LiteralPath $WrapperPath -Algorithm SHA256).Hash | Should -Be 'C911C48D7B2D285B03FF6417F2467ACC50520995F83A55EDAB195D82F38A6755'
    $Info = Get-TauriExecutableInfo -Path $ApplicationPath
    Test-TauriExecutable -Path $ApplicationPath | Should -BeTrue
    Test-TauriExecutable -Path $WrapperPath | Should -BeFalse
    $Info.BundleType | Should -Be 'NSIS'
    $Info.BundleTypeMarker.Format | Should -Be 'LongToken'
    $Info.BundleTypeMarker.IsRuntimeValue | Should -BeTrue
    $Info.BundleTypeEvidenceConfidence | Should -Be 'high'
    $Info.AuxiliaryMaps[0].Type | Should -Be 'HtmlCspHashMap'
    $Info.Diagnostics.Id | Should -Not -Contain 'Tauri.BundleType.Conflict'
  }
}
