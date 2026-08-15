BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Cabinet.psm1') -Force
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'MSI.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'InstallShield.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'InstallShieldInstallScript.psm1') -Force

  $Script:FixtureDirectory = $TestDrive
  $Script:InstallShieldBuilderRoot = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\InstallShield'
  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [string]$Sha256
    )

    $Arguments = @{ RelativePath = Resolve-DumplingsTestFixtureCatalogPath -Name $Name; Uri = $Url }
    if ($Sha256) { $Arguments.Sha256 = $Sha256 }
    Get-DumplingsTestFixture @Arguments
  }

  function Get-CastleDriverInstallerFixture {
    $Archive = Get-InstallerFixture -Name 'CastleDriver.zip' -Url 'https://linklydownloads.z8.web.core.windows.net/drivers/CastleDriver.zip' -Sha256 '245A969AD612266AE81177BA2A351E27E965AA887DC5ABB6584085E72D11A73C'
    $FixtureRoot = Join-Path $Script:FixtureDirectory 'CastleDriver'
    $ExpectedFiles = @(
      [pscustomobject]@{ Architecture = 'x64'; EntryName = 'CAS_CDC_Driver/x64/setup.exe'; Sha256 = 'AA039ADC254B2F5D918FD7D62346F976F30F09E42C99BB8F078FD6581D8B0CB9'; DisplayVersion = '20.1.6001'; ProductCode = '{0B50AE89-8435-4295-AAEB-8BA4ABA283B8}'; UpgradeCode = '{B332D044-2B75-4AD2-8D7E-AC64F82FBF57}' }
      [pscustomobject]@{ Architecture = 'x86'; EntryName = 'CAS_CDC_Driver/x86/setup.exe'; Sha256 = 'A402397011B5EB9B8BCA3EB080C65B208101F1A100FC7B1573F35526AAAB1FD9'; DisplayVersion = '20.1.3001'; ProductCode = '{F9E45BF2-E8C0-43FF-8502-809DB2123265}'; UpgradeCode = '{63DA7213-8D1A-4BF5-8A2E-AD7B1E959A6E}' }
    )

    $Zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
      foreach ($ExpectedFile in $ExpectedFiles) {
        $Destination = Join-Path $FixtureRoot "$($ExpectedFile.Architecture)\setup.exe"
        if (-not (Test-Path -LiteralPath $Destination -PathType Leaf) -or
          (Get-DumplingsTestFixtureHash -Path $Destination) -ne $ExpectedFile.Sha256) {
          $Entry = $Zip.GetEntry($ExpectedFile.EntryName)
          if (-not $Entry) { throw "The CastleDriver archive does not contain '$($ExpectedFile.EntryName)'." }

          $null = New-Item -Path (Split-Path -Path $Destination -Parent) -ItemType Directory -Force
          $InputStream = $Entry.Open()
          $OutputStream = [IO.File]::Create($Destination)
          try { $InputStream.CopyTo($OutputStream) } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
        }

        Get-DumplingsTestFixtureHash -Path $Destination | Should -Be $ExpectedFile.Sha256
        $ExpectedFile | Add-Member -NotePropertyName Path -NotePropertyValue $Destination -PassThru
      }
    } finally {
      $Zip.Dispose()
    }
  }

  function New-TestInstallShieldSpannedCabinet {
    param ([Parameter(Mandatory)][string]$Path)

    $Payload = [Text.Encoding]::UTF8.GetBytes(('Dumplings split InstallShield cabinet payload. ' * 256))
    $CompressedStream = [IO.MemoryStream]::new()
    try {
      $Deflater = [IO.Compression.DeflateStream]::new($CompressedStream, [IO.Compression.CompressionLevel]::Optimal, $true)
      try { $Deflater.Write($Payload, 0, $Payload.Length) } finally { $Deflater.Dispose() }
      $Compressed = $CompressedStream.ToArray()
    } finally {
      $CompressedStream.Dispose()
    }
    if ($Compressed.Length -gt [uint16]::MaxValue) { throw 'The synthetic InstallShield compressed block is too large.' }
    $Stored = [byte[]]::new($Compressed.Length + 2)
    [BitConverter]::GetBytes([uint16]$Compressed.Length).CopyTo($Stored, 0)
    $Compressed.CopyTo($Stored, 2)

    $Directory = Split-Path -Path $Path -Parent
    $DescriptorBase = 0x20
    $TableOffset = 0x100
    $TableBase = $DescriptorBase + $TableOffset
    $DescriptorTableOffset = 0x100
    $RecordSize = 0x57
    $Header = [byte[]]::new(0x500)
    $WriteUInt16 = { param([byte[]]$Bytes, [int]$Offset, [uint16]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt32 = { param([byte[]]$Bytes, [int]$Offset, [uint32]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt64 = { param([byte[]]$Bytes, [int]$Offset, [uint64]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteString = {
      param([byte[]]$Bytes, [int]$Offset, [string]$Value)
      [Text.Encoding]::Unicode.GetBytes($Value + [char]0).CopyTo($Bytes, $Offset)
    }

    # data1.hdr contains one compressed split descriptor and one linked alias.
    & $WriteUInt32 $Header 0 ([uint32]0x28635349)
    & $WriteUInt32 $Header 4 ([uint32]0x04000C80)
    & $WriteUInt32 $Header 12 ([uint32]$DescriptorBase)
    & $WriteUInt32 $Header 16 ([uint32]($Header.Length - $DescriptorBase))
    & $WriteUInt32 $Header ($DescriptorBase + 0x0C) ([uint32]$TableOffset)
    & $WriteUInt32 $Header ($DescriptorBase + 0x14) ([uint32]0x1C0)
    & $WriteUInt32 $Header ($DescriptorBase + 0x18) ([uint32]0x1C0)
    & $WriteUInt32 $Header ($DescriptorBase + 0x1C) ([uint32]1)
    & $WriteUInt32 $Header ($DescriptorBase + 0x28) ([uint32]2)
    & $WriteUInt32 $Header ($DescriptorBase + 0x2C) ([uint32]$DescriptorTableOffset)
    & $WriteUInt32 $Header $TableBase ([uint32]0x10)
    & $WriteString $Header ($TableBase + 0x10) 'payload'
    & $WriteString $Header ($TableBase + 0x30) 'split.bin'
    & $WriteString $Header ($TableBase + 0x60) 'alias.bin'

    $Digest = [Security.Cryptography.MD5]::HashData($Payload)
    foreach ($Record in @(
        @{ Index = 0; NameOffset = 0x30; Flags = 5; LinkPrevious = 0; LinkFlags = 0 }
        @{ Index = 1; NameOffset = 0x60; Flags = 4; LinkPrevious = 0; LinkFlags = 1 }
      )) {
      $Offset = $TableBase + $DescriptorTableOffset + $Record.Index * $RecordSize
      & $WriteUInt16 $Header $Offset ([uint16]$Record.Flags)
      & $WriteUInt64 $Header ($Offset + 2) ([uint64]$Payload.Length)
      & $WriteUInt64 $Header ($Offset + 10) ([uint64]$Stored.Length)
      & $WriteUInt64 $Header ($Offset + 18) ([uint64]84)
      $Digest.CopyTo($Header, $Offset + 26)
      & $WriteUInt32 $Header ($Offset + 58) ([uint32]$Record.NameOffset)
      & $WriteUInt16 $Header ($Offset + 62) ([uint16]0)
      & $WriteUInt32 $Header ($Offset + 76) ([uint32]$Record.LinkPrevious)
      $Header[$Offset + 84] = [byte]$Record.LinkFlags
      & $WriteUInt16 $Header ($Offset + 85) ([uint16]1)
    }
    [IO.File]::WriteAllBytes($Path, $Header)

    # Split the stored Deflate frame after its first length byte. This proves
    # the logical stream, rather than the decompressor, owns volume traversal.
    $SplitAt = 1
    foreach ($Volume in 1, 2) {
      $Start = $Volume -eq 1 ? 0 : $SplitAt
      $Count = $Volume -eq 1 ? $SplitAt : $Stored.Length - $SplitAt
      $Cabinet = [byte[]]::new(84 + $Count)
      & $WriteUInt32 $Cabinet 0 ([uint32]0x28635349)
      & $WriteUInt32 $Cabinet 4 ([uint32]0x04000C80)
      & $WriteUInt32 $Cabinet 28 ([uint32]0)
      & $WriteUInt32 $Cabinet 32 ([uint32]0)
      foreach ($Offset in 36, 60) { & $WriteUInt64 $Cabinet $Offset ([uint64]84) }
      foreach ($Offset in 44, 68) { & $WriteUInt64 $Cabinet $Offset ([uint64]$Payload.Length) }
      foreach ($Offset in 52, 76) { & $WriteUInt64 $Cabinet $Offset ([uint64]$Count) }
      [Array]::Copy($Stored, $Start, $Cabinet, 84, $Count)
      [IO.File]::WriteAllBytes((Join-Path $Directory "data$Volume.cab"), $Cabinet)
    }

    return [pscustomobject]@{ Payload = $Payload; StoredLength = $Stored.Length }
  }

  function New-TestInstallShield5Cabinet {
    param ([Parameter(Mandatory)][string]$Path)

    $Payload = [Text.Encoding]::UTF8.GetBytes('InstallShield 5 legacy descriptor payload.')
    $CompressedStream = [IO.MemoryStream]::new()
    try {
      $Deflater = [IO.Compression.DeflateStream]::new($CompressedStream, [IO.Compression.CompressionLevel]::Optimal, $true)
      try { $Deflater.Write($Payload, 0, $Payload.Length) } finally { $Deflater.Dispose() }
      $Compressed = $CompressedStream.ToArray()
    } finally { $CompressedStream.Dispose() }

    $DescriptorBase = 0x20
    $TableOffset = 0x40
    $TableBase = $DescriptorBase + $TableOffset
    $DescriptorSize = 0x240
    $Header = [byte[]]::new($DescriptorBase + $DescriptorSize)
    $WriteUInt16 = { param([byte[]]$Bytes, [int]$Offset, [uint16]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }
    $WriteUInt32 = { param([byte[]]$Bytes, [int]$Offset, [uint32]$Value) [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset) }

    # Version 5 places one 0x3A file record at the file offset-table entry.
    & $WriteUInt32 $Header 0 ([uint32]0x28635349)
    & $WriteUInt32 $Header 4 ([uint32]0x01005000)
    & $WriteUInt32 $Header 12 ([uint32]$DescriptorBase)
    & $WriteUInt32 $Header 16 ([uint32]$DescriptorSize)
    & $WriteUInt32 $Header ($DescriptorBase + 0x0C) ([uint32]$TableOffset)
    & $WriteUInt32 $Header ($DescriptorBase + 0x14) ([uint32]0x180)
    & $WriteUInt32 $Header ($DescriptorBase + 0x18) ([uint32]0x180)
    & $WriteUInt32 $Header ($DescriptorBase + 0x1C) ([uint32]1)
    & $WriteUInt32 $Header ($DescriptorBase + 0x28) ([uint32]1)
    & $WriteUInt32 $Header $TableBase ([uint32]0x10)
    & $WriteUInt32 $Header ($TableBase + 4) ([uint32]0x40)
    [Text.Encoding]::Latin1.GetBytes("payload$([char]0)").CopyTo($Header, $TableBase + 0x10)
    [Text.Encoding]::Latin1.GetBytes("legacy.bin$([char]0)").CopyTo($Header, $TableBase + 0x20)
    $Record = $TableBase + 0x40
    & $WriteUInt32 $Header $Record ([uint32]0x20)
    & $WriteUInt16 $Header ($Record + 4) ([uint16]0)
    & $WriteUInt16 $Header ($Record + 8) ([uint16]4)
    & $WriteUInt32 $Header ($Record + 10) ([uint32]$Payload.Length)
    & $WriteUInt32 $Header ($Record + 14) ([uint32]$Compressed.Length)
    & $WriteUInt32 $Header ($Record + 38) ([uint32]60)
    [Security.Cryptography.MD5]::HashData($Payload).CopyTo($Header, $Record + 42)
    [IO.File]::WriteAllBytes($Path, $Header)

    # The version-5 volume header is 40 bytes after the common 20-byte header.
    $Cabinet = [byte[]]::new(60 + $Compressed.Length)
    & $WriteUInt32 $Cabinet 0 ([uint32]0x28635349)
    & $WriteUInt32 $Cabinet 4 ([uint32]0x01005000)
    & $WriteUInt32 $Cabinet 28 ([uint32]0)
    & $WriteUInt32 $Cabinet 32 ([uint32]0)
    & $WriteUInt32 $Cabinet 36 ([uint32]60)
    & $WriteUInt32 $Cabinet 40 ([uint32]$Payload.Length)
    & $WriteUInt32 $Cabinet 44 ([uint32]$Compressed.Length)
    & $WriteUInt32 $Cabinet 48 ([uint32]60)
    & $WriteUInt32 $Cabinet 52 ([uint32]$Payload.Length)
    & $WriteUInt32 $Cabinet 56 ([uint32]$Compressed.Length)
    $Compressed.CopyTo($Cabinet, 60)
    [IO.File]::WriteAllBytes((Join-Path (Split-Path -Path $Path -Parent) 'data1.cab'), $Cabinet)
    return $Payload
  }

  function New-TestInstallShieldClassicArchive {
    param ([Parameter(Mandatory)][string]$Path)

    # This TTCOMP stream is the bounded blast reference vector and expands to
    # AIAIAIAIAIAIA. The 27-byte footer record immediately precedes A.TXT\0.
    $Bytes = [byte[]](0x00, 0x04, 0x82, 0x24, 0x25, 0x8F, 0x80, 0x7F, 0x0D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x05, 0x41, 0x2E, 0x54, 0x58, 0x54, 0x00)
    [IO.File]::WriteAllBytes($Path, $Bytes)
  }
}
