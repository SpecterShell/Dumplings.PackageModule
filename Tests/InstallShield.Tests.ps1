BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Infrastructure\Cabinet.psm1') -Force
  . (Join-Path $PSScriptRoot 'Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Installers' 'MSI.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Installers' 'InstallShield.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Installers' 'InstallShieldInstallScript.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallShield'
  $Script:MsiFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\MSI'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [string]$Sha256
    )

    $Arguments = @{ Directory = $Script:FixtureDirectory; Name = $Name; Uri = $Url }
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

Describe 'InstallShield release and structural classification' {
  It 'maps every source-backed project schema without collapsing reported aliases' {
    $ExpectedReleases = [ordered]@{
      755 = @('InstallShield DevStudio 9')
      761 = @('InstallShield 11')
      763 = @('InstallShield 11.5')
      765 = @('InstallShield 12')
      766 = @('InstallShield 2008')
      767 = @('InstallShield 2008')
      768 = @('InstallShield 2009')
      769 = @('InstallShield 2010')
      770 = @('InstallShield 2010')
      771 = @('InstallShield 2011')
      772 = @('InstallShield 2012')
      773 = @('InstallShield 2012 Spring')
      774 = @('InstallShield 2013')
      775 = @('InstallShield 2014')
      776 = @('InstallShield 2015')
      777 = @('InstallShield 2016')
      778 = @('InstallShield 2018 R1')
      779 = @('InstallShield 2018 R2')
      780 = @('InstallShield 2019')
      783 = @('InstallShield 2020 R1')
      784 = @('InstallShield 2020 R2', 'InstallShield 2020 R3')
      787 = @('InstallShield 2022 R2')
      789 = @('InstallShield 2023 R2')
      791 = @('InstallShield 2025 R1')
      792 = @('InstallShield 2026 R1')
    }

    foreach ($Entry in $ExpectedReleases.GetEnumerator()) {
      $Candidates = InModuleScope InstallShield { param($Version) Get-InstallShieldSchemaReleaseCandidate -SchemaVersion $Version } -Parameters @{ Version = $Entry.Key }
      $Candidates.Name | Should -Be $Entry.Value
    }
  }

  It 'reads schema versions only from a structured InstallShield project table' {
    $Project = Join-Path $TestDrive 'sample.ism'
    @'
<?xml version="1.0" encoding="UTF-8"?>
<msi><table name="InstallShield"><row><td>SchemaVersion</td><td>792</td></row></table></msi>
'@.Trim() | Set-Content -LiteralPath $Project -NoNewline

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.ProductVersion | Should -Be '32'
    $Release.SchemaVersion | Should -Be 792
    $Release.SourceFormat | Should -Be 'Xml'
    $Release.Confidence | Should -Be 'Authoritative'
  }

  It 'reads SchemaVersion from an official binary InstallShield project database' {
    $Project = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\Othello.ism'
    if (-not (Test-Path -LiteralPath $Project -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11.5 binary project fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Project | Should -Be '3A031CAB6DEEBCFCF9C7CCE1FD06D43B60D966B21973D293970A0BA35F8C50EA'

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.SchemaVersion | Should -Be 763
    $Release.ReleaseName | Should -Be 'InstallShield 11.5'
    $Release.SourceFormat | Should -Be 'WindowsInstallerDatabase'
  }

  It 'rejects an arbitrary file that merely contains a SchemaVersion string' {
    $Path = Join-Path $TestDrive 'not-a-project.exe'
    [IO.File]::WriteAllText($Path, 'SchemaVersion=792')
    { Get-InstallShieldProjectReleaseInfo -Path $Path } | Should -Throw
  }

  It 'preserves an unmapped structured schema value for future classification' {
    $Project = Join-Path $TestDrive 'future.ism'
    '<msi><table name="InstallShield"><row><td>SchemaVersion</td><td>999</td></row></table></msi>' |
      Set-Content -LiteralPath $Project -NoNewline

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.SchemaVersion | Should -Be 999
    $Release.ReleaseName | Should -BeNullOrEmpty
    $Release.Confidence | Should -Be 'Unknown'
  }

  It 'distinguishes incomplete binary templates and proprietary project representations' {
    $EmptyProject = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\IsBlank.ism'
    $ProprietaryProject = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\Phobos.ism'
    if (-not (Test-Path -LiteralPath $EmptyProject -PathType Leaf) -or -not (Test-Path -LiteralPath $ProprietaryProject -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11.5 project-template fixtures are unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $EmptyProject | Should -Be '61996698AA765F6202C470194BEAFCDE6D26BF610B11E99918DAA3F543D51852'
    Get-DumplingsTestFixtureHash -Path $ProprietaryProject | Should -Be 'C24301D7B9E690B833A7E18309FA5BBF1FF266C405F8BB811AE9793ACCA27F09'

    { Get-InstallShieldProjectReleaseInfo -Path $EmptyProject } | Should -Throw '*does not contain a readable InstallShield.SchemaVersion row*'
    { Get-InstallShieldProjectReleaseInfo -Path $ProprietaryProject } | Should -Throw '*unsupported structured representation*'
  }

  It 'recognizes the cached official InstallShield 2026 R1 project schema' {
    $Project = Join-Path $Script:FixtureDirectory 'BuilderDifferential\Baseline2\ALLUSERS Sample Project.ism'
    if (-not (Test-Path -LiteralPath $Project -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 2026 R1 project fixture is unavailable.'
      return
    }

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.SchemaVersion | Should -Be 792
    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.Confidence | Should -Be 'Authoritative'
  }

  It 'preserves reported schema aliases without inventing a conflict' {
    foreach ($SchemaVersion in 769, 770) {
      $Candidates = InModuleScope InstallShield { param($Version) Get-InstallShieldSchemaReleaseCandidate -SchemaVersion $Version } -Parameters @{ Version = $SchemaVersion }
      $Candidates.Name | Should -Be 'InstallShield 2010'
      $Candidates.Confidence | Should -Be 'ReportedAlias'
    }
    $Candidates = InModuleScope InstallShield { Get-InstallShieldSchemaReleaseCandidate -SchemaVersion 784 }
    $Candidates.Name | Should -Be @('InstallShield 2020 R2', 'InstallShield 2020 R3')
  }

  It 'keeps conflicting release evidence separate from structural dispatch' {
    $Release = InModuleScope InstallShield {
      $First = ConvertTo-InstallShieldReleaseEvidence -Source ProjectSchema -Value 792 -Candidate ([pscustomobject]@{ Name = 'InstallShield 2026 R1'; ProductVersion = '32'; Year = 2026 }) -Confidence Authoritative -Rank 120 -Detail Project
      $Second = ConvertTo-InstallShieldReleaseEvidence -Source CabinetHeader -Value 6 -Candidate ([pscustomobject]@{ Name = 'InstallShield Professional 6'; ProductVersion = '6'; Year = 1999 }) -Confidence StructuralMediaVersion -Rank 90 -Detail Media
      Resolve-InstallShieldRelease -Evidence @($First, $Second)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.Confidence | Should -Be 'Conflicting'
    $Release.Warnings | Should -Match 'Structural routes remain authoritative'
  }

  It 'does not treat a cabinet format generation as a builder product release' {
    $Release = InModuleScope InstallShield {
      $Media = ConvertTo-InstallShieldReleaseEvidence -Source CabinetHeader -Value ([uint32]0x01009500) -Candidate $null `
        -Confidence StructuralMediaVersion -Rank 0 -Detail 'ISc( cabinet format 9'
      $RuntimeCandidate = Get-InstallShieldProductReleaseCandidate -ProductVersion '11.50.0' | Select-Object -First 1
      $Runtime = ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value '11.50.0' -Candidate $RuntimeCandidate `
        -Confidence TrustedRuntimeVersion -Rank 50 -Detail Runtime
      Resolve-InstallShieldRelease -Evidence @($Media, $Runtime)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 11.5'
    $Release.Confidence | Should -Be 'TrustedRuntimeVersion'
    $Release.Evidence | Where-Object Source -EQ CabinetHeader | Select-Object -ExpandProperty ReleaseName | Should -BeNullOrEmpty
    $Release.Warnings | Should -BeNullOrEmpty
  }

  It 'uses compatible runtime detail without replacing stronger release identity' {
    $Release = InModuleScope InstallShield {
      $Candidate = [pscustomobject]@{ Name = 'InstallShield 2026 R1'; ProductVersion = '32'; Year = 2026 }
      $Schema = ConvertTo-InstallShieldReleaseEvidence -Source ProjectSchema -Value 792 -Candidate $Candidate -Confidence Authoritative -Rank 120 -Detail Project
      $Runtime = ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value '32.0 SP2.144' -Candidate $Candidate -Confidence TrustedRuntimeVersion -Rank 50 -Detail Runtime
      $Runtime.ServicePack = '2'
      $Runtime.Build = '144'
      Resolve-InstallShieldRelease -Evidence @($Schema, $Runtime)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.SchemaVersion | Should -Be 792
    $Release.ServicePack | Should -Be '2'
    $Release.Build | Should -Be '144'
  }

  It 'uses source-backed product and file versions from official runtime stubs' {
    $Cases = @(
      [pscustomobject]@{ Path = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\RuntimeStubs\setup-7.exe'; Hash = 'CFB39234D54F3D968B405FD197078AF8C4B87A19BD4F0752FE4935BC4EB757B9'; Release = 'InstallShield Developer 7'; Build = '262' }
      [pscustomobject]@{ Path = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\RuntimeStubs\setup-8.exe'; Hash = '327564AAE042851953F52D1C030913EBE127F95521FEFAF4EE2BF55A640CBF79'; Release = 'InstallShield Developer 8'; Build = '160' }
      [pscustomobject]@{ Path = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\RuntimeStubs\setup-9.exe'; Hash = '90AEE2AE77B05500DB7D5623B7B152229207C24529D433542FDEAD722219F1F6'; Release = 'InstallShield DevStudio 9'; Build = '333' }
      [pscustomobject]@{ Path = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\RuntimeStubs\setup-10.exe'; Hash = 'FA240AABE0C6B20D556D72CF3954BB440756E852D49957F841EC4E13351AA1F0'; Release = 'InstallShield X/10.5'; Build = '238' }
      [pscustomobject]@{ Path = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\RuntimeStubs\setup-11.exe'; Hash = '0639408923040D69FFDC18A1F57ECA4E598489A649BD4C3476401A7F415B62BA'; Release = 'InstallShield 11'; Build = '28844' }
      [pscustomobject]@{ Path = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\setup.dll'; Hash = '47B4E860B81058CFF4D52DE76764EC801D0A26549214D80356D05FCBEAA3CC60'; Release = 'InstallShield 11.5'; Build = '42618' }
      [pscustomobject]@{ Path = Join-Path $Script:FixtureDirectory 'BuilderReference\2026R1\setup.exe'; Hash = 'CAA788B72688266BD6BDFD6BD11820B4A79132BD97D95C1AE058E66EF5BE5CA8'; Release = 'InstallShield 2026'; Build = '68' }
    )
    foreach ($Case in $Cases) {
      if (-not (Test-Path -LiteralPath $Case.Path -PathType Leaf)) {
        Set-ItResult -Skipped -Because "The official runtime fixture '$($Case.Path)' is unavailable."
        return
      }
      Get-DumplingsTestFixtureHash -Path $Case.Path | Should -Be $Case.Hash
      $Evidence = InModuleScope InstallShield -Parameters @{ RuntimePath = $Case.Path } {
        param($RuntimePath)
        Get-InstallShieldRuntimeReleaseEvidence -Path $RuntimePath | Select-Object -First 1
      }
      $Evidence.ReleaseName | Should -Be $Case.Release
      $Evidence.Build | Should -Be $Case.Build
    }
  }

  It 'keeps classic and future cabinet profiles as independent structural routes' {
    $Routes = InModuleScope InstallShield {
      $Context = [pscustomobject]@{
        PackageForTheWebCabinet = $null
        Extraction              = $null
        Classic3Info            = [pscustomobject]@{
          SupportStatus = 'Supported'
          Evidence      = @([pscustomobject]@{ Signature = 'Setup30 footer' })
          Limitations   = @()
          Entries       = @([pscustomobject]@{ Name = 'setup.ins' })
        }
        CabinetSupport          = [pscustomobject]@{
          MediaVersions = @([pscustomobject]@{
              MajorVersion  = 33
              RawVersion    = [uint32]0x01021000
              SupportStatus = 'Partial'
              Limitations   = @('Future catalog extensions are unresolved.')
            })
        }
        InstallScriptHeaders    = @()
        SelectedMsiInfo         = $null
        AdvancedUiInfo          = $null
      }
      Get-InstallShieldStructuralRoute -Context $Context -Result ([pscustomobject]@{ InstallScriptInfo = $null })
    }

    $Routes.RouteId | Should -Be @('Classic3/Package', 'Classic3/INS', 'Cabinet17/UnicodeCatalog')
    ($Routes | Where-Object RouteId -EQ 'Classic3/INS').SupportStatus | Should -Be 'Supported'
    ($Routes | Where-Object RouteId -EQ 'Cabinet17/UnicodeCatalog').SupportStatus | Should -Be 'Partial'
    ($Routes | Where-Object RouteId -EQ 'Cabinet17/UnicodeCatalog').Limitations | Should -Contain 'Future catalog extensions are unresolved.'
  }
}

Describe 'InstallShield parser' {
  It 'rejects a trusted launcher whose Setup.ini has no direct external payload evidence' {
    $RuntimeFixture = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\RuntimeStubs\setup-11.exe'
    if (-not (Test-Path -LiteralPath $RuntimeFixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11 runtime fixture is unavailable.'
      return
    }
    $MediaRoot = Join-Path $TestDrive 'incomplete-external-media'
    $null = New-Item -Path (Join-Path $MediaRoot 'unrelated') -ItemType Directory -Force
    Copy-Item -LiteralPath $RuntimeFixture -Destination (Join-Path $MediaRoot 'setup.exe')
    "[Startup]`r`nEngineVersion=11.00`r`nPackageName=Missing.msi`r`n" | Set-Content -LiteralPath (Join-Path $MediaRoot 'Setup.ini') -NoNewline
    [IO.File]::WriteAllText((Join-Path $MediaRoot 'unrelated\setup.inx'), 'not direct media')

    $ExternalMedia = InModuleScope InstallShield -Parameters @{ InstallerPath = Join-Path $MediaRoot 'setup.exe' } {
      param($InstallerPath)
      Get-InstallShieldExternalMediaInfo -Path $InstallerPath
    }

    $ExternalMedia | Should -BeNullOrEmpty
  }

  It 'routes official 11.5 external InstallScript media without scanning the sibling directory' {
    $FixtureRoot = Join-Path $Script:FixtureDirectory 'BuilderReference\11.5\DialogSamplerDefault'
    $Fixture = Join-Path $FixtureRoot 'setup.exe'
    $Header = Join-Path $FixtureRoot 'data1.hdr'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf) -or -not (Test-Path -LiteralPath $Header -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11.5 Dialog Sampler media fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be '9F592BA27A79B32D11FAFA59FACBBEBDC9902410E37E2EAFA22E677FC33F47E6'
    Get-DumplingsTestFixtureHash -Path $Header | Should -Be 'EB1D501D8D01B9EEFFE7C2A3A5C1B345C20016894E0F5DD54A7272CEB59A3C7E'

    $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath (Join-Path $TestDrive 'dialog-sampler')

    $Info.ContainerFormat | Should -Be 'InstallShield External Media'
    $Info.Variant | Should -Be 'InstallScript'
    $Info.InstallShieldProjectType | Should -Be 'InstallScript'
    $Info.ProductCode | Should -Be '{40F1A2C0-2DB0-11D3-803F-00104B1F989C}'
    $Info.DisplayName | Should -Be 'InstallShield Dialog Sampler'
    $Info.Publisher | Should -Be 'Macrovision'
    $Info.ExternalMediaInfo.EngineVersion | Should -Be '11.50.0.42618'
    $Info.ExternalMediaInfo.MediaRoot | Should -Be $FixtureRoot
    $Info.InxFiles | Should -HaveCount 1
    $Info.InxFiles[0] | Should -Be (Join-Path $FixtureRoot 'setup.inx')
    $Info.InstallShieldCabinetSupport.CatalogEntryCount | Should -Be 57
    $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 11.5'
    $Info.InstallShieldRelease.Build | Should -Be '42618'
    $Info.InstallShieldRelease.Confidence | Should -Be 'StructuredEngineVersion'
    $Info.InstallShieldRelease.Warnings | Should -BeNullOrEmpty
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Be @('Media/External', 'Cabinet6/AnsiCatalog', 'Script/aLuZ')
  }

  It 'routes archived 6.10 uppercase external media through the ANSI catalog and aLuZ script' {
    $FixtureRoot = Join-Path $Script:FixtureDirectory 'BuilderArchives\6.10\Media'
    $Fixture = Join-Path $FixtureRoot 'SETUP.EXE'
    $Header = Join-Path $FixtureRoot 'DATA1.HDR'
    $SecondVolume = Join-Path $FixtureRoot 'DATA2.CAB'
    $Inx = Join-Path $FixtureRoot 'SETUP.INX'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf) -or -not (Test-Path -LiteralPath $Header -PathType Leaf) -or -not (Test-Path -LiteralPath $SecondVolume -PathType Leaf) -or -not (Test-Path -LiteralPath $Inx -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The archived InstallShield Professional 6.10 media fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be '20B0C376813A4DAC5387E48D504AED1DD5380AE11EA0E4EAB05DF81CD0BF0D53'
    Get-DumplingsTestFixtureHash -Path $Header | Should -Be 'B32620024598F5D492B44950CADBF791800553BAE51860811B0852F74C4ED334'
    Get-DumplingsTestFixtureHash -Path $SecondVolume | Should -Be '1207D1865DC7E397B2C79EE873649224E9DE389A492F737AC2E04564CC6AF08C'
    Get-DumplingsTestFixtureHash -Path $Inx | Should -Be 'EB4096111984AD9C989C9F9421CCB97FBF210B1A63ED744C4CADE7A2D0787EE6'

    $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath (Join-Path $TestDrive 'installshield-610')

    $Info.ContainerFormat | Should -Be 'InstallShield External Media'
    $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield Professional 6'
    $Info.InstallShieldRelease.Build | Should -Be '100.1249'
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Be @('Media/External', 'Cabinet6/AnsiCatalog', 'Script/aLuZ')
    $Info.InstallShieldCabinetSupport.CatalogEntryCount | Should -Be 2014
    $Info.InstallShieldCabinetSupport.MediaVersions.RawVersion | Should -Be ([uint32]0x0100600C)
    $Info.InstallShieldCabinetSupport.MediaVersions.StructuralProfile | Should -Be 'AnsiCatalog'
    $Info.InstallShieldCabinetSupport.MediaVersions.Limitations | Should -Match 'generation-specific optional registry and shell pointer layouts'
    $Info.InstallShieldCabinetSupport.Warnings | Should -BeNullOrEmpty
    $Info.InstallScriptInfo.ParserVersionInfo.HeaderKind | Should -Be 'aLuZ'
    $Info.InstallScriptInfo.ParserVersionInfo.InstructionCount | Should -BeGreaterThan 10000
    $Info.UnsupportedOpcodes | Should -BeNullOrEmpty

    $SelectedDestination = Join-Path $TestDrive 'installshield-610-selected'
    $null = Expand-InstallShieldCabinet -Path $Header -DestinationPath $SelectedDestination -Name '_disk1.cdf' -CollisionAction Error
    Get-DumplingsTestFixtureHash -Path (Join-Path $SelectedDestination '_disk1.cdf') | Should -Be 'D461C503977AD961D41F8ECDBF2AFAECA75DD5AB5BF1A6837CEF741D7B67EE2E'
  }

  It 'classifies the official InstallShield 3 engine without treating it as package media' {
    $Fixture = Join-Path $Script:FixtureDirectory 'Classic3\setup32.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 3 engine fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be '3AAA614FDF6986017CBE6ADE045D404F08872E6A90D6A0D54C30E438A2BDEE65'
    $Destination = Join-Path $TestDrive 'classic-engine'

    $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $Destination

    $Info.ContainerFormat | Should -Be 'InstallShield 3 Engine'
    $Info.Variant | Should -Be 'InstallShield 3 engine without package media'
    $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 3'
    $Info.InstallShieldRelease.Build | Should -Be '117'
    $Info.InstallShieldStructuralRoutes.RouteId | Should -Be 'Classic3/Engine'
    $Info.InstallShieldStructuralRoutes.SupportStatus | Should -Be 'Partial'
    $Info.ExtractedFiles | Should -BeNullOrEmpty
    $Info.Warnings | Should -Match 'without a validated embedded Setup30 package'
  }

  It 'extracts InstallShield 3 Setup30 footer members through bounded TTCOMP decoding' {
    $Archive = Join-Path $TestDrive 'data.z'
    $Destination = Join-Path $TestDrive 'classic-expanded'
    New-TestInstallShieldClassicArchive -Path $Archive

    $Info = Get-InstallShieldClassicArchiveInfo -Path $Archive
    $Files = @(Expand-InstallShieldClassicArchive -Path $Archive -DestinationPath $Destination -CollisionAction Error)

    $Info.Profile | Should -Be 'Setup30FooterTtComp'
    $Info.Entries.Name | Should -Be 'A.TXT'
    [IO.File]::ReadAllText($Files[0]) | Should -Be 'AIAIAIAIAIAIA'
  }

  It 'rejects a truncated InstallShield 3 footer without scanning beyond the bounded tail' {
    $Archive = Join-Path $TestDrive 'truncated-data.z'
    [IO.File]::WriteAllBytes($Archive, [byte[]](0x00, 0x04, 0x82, 0x24, 0x25, 0x8F))

    { Get-InstallShieldClassicArchiveInfo -Path $Archive } | Should -Throw '*no validated Setup30 footer entries*'
  }

  It 'extracts InstallShield 5 descriptors and raw-Deflate volume records' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $Expected = New-TestInstallShield5Cabinet -Path $HeaderPath
    $Destination = Join-Path $TestDrive 'legacy-five-expanded'

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($HeaderPath)
    $null = Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath $Destination -CollisionAction Error

    $Inspection.MediaMetadata.RawVersion | Should -Be ([uint32]0x01005000)
    $Inspection.MediaMetadata.MajorVersion | Should -Be 5
    $Inspection.MediaMetadata.StructuralProfile | Should -Be 'LegacyDescriptor'
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\legacy.bin')) | Should -Be $Expected
  }

  It 'catalogs and extracts an archived pre-digest InstallShield 5 cabinet' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderArchives\5\IS5pro_u\data1.cab'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The extracted InstallShield 5 Professional cabinet fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be 'A6DEC4E8A2D7BC4810711DD5F4F10F71F7A8E52A6B9B834AE306CA5076A66B0E'
    $Destination = Join-Path $TestDrive 'legacy-zero-expanded'

    $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($Fixture)
    $null = Expand-InstallShieldCabinet -Path $Fixture -DestinationPath $Destination -Name 'Version.txt' -CollisionAction Error

    $Inspection.Entries.Count | Should -Be 451
    @($Inspection.Entries | Where-Object IsValid).Count | Should -Be 351
    $Inspection.MediaMetadata.RawVersion | Should -Be ([uint32]0x01000004)
    $Inspection.MediaMetadata.MajorVersion | Should -Be 0
    $Inspection.MediaMetadata.StructuralProfile | Should -Be 'LegacyDescriptorWithoutDigest'
    [IO.File]::ReadAllText((Join-Path $Destination 'Version.txt')) | Should -Be "[Version]`r`nBuild=200"
  }

  It 'rejects an InstallShield 5 descriptor whose expanded-data MD5 is incorrect' {
    $HeaderPath = Join-Path $TestDrive 'bad-md5\data1.hdr'
    $null = New-Item -Path (Split-Path -Path $HeaderPath -Parent) -ItemType Directory -Force
    $null = New-TestInstallShield5Cabinet -Path $HeaderPath
    $Header = [IO.File]::ReadAllBytes($HeaderPath)
    # Descriptor starts at 0xA0 in the generated fixture; MD5 is +0x2A.
    $Header[0xCA] = $Header[0xCA] -bxor 0xFF
    [IO.File]::WriteAllBytes($HeaderPath, $Header)

    { Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath (Join-Path $TestDrive 'bad-md5-expanded') -CollisionAction Error } |
      Should -Throw '*MD5*'
  }
  It 'streams compressed split entries across volumes and resolves linked aliases' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $Fixture = New-TestInstallShieldSpannedCabinet -Path $HeaderPath
    $Destination = Join-Path $TestDrive 'spanned-expanded'

    $Result = Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath $Destination -CollisionAction Error

    $Result | Should -Be (Get-Item -LiteralPath $Destination).FullName
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\split.bin')) | Should -Be $Fixture.Payload
    [IO.File]::ReadAllBytes((Join-Path $Destination 'payload\alias.bin')) | Should -Be $Fixture.Payload
  }

  It 'rejects cyclic InstallShield cabinet link chains before opening payload volumes' {
    $HeaderPath = Join-Path $TestDrive 'data1.hdr'
    $null = New-TestInstallShieldSpannedCabinet -Path $HeaderPath
    $Header = [IO.File]::ReadAllBytes($HeaderPath)
    $FirstDescriptor = 0x20 + 0x100 + 0x100
    [BitConverter]::GetBytes([uint32]1).CopyTo($Header, $FirstDescriptor + 76)
    $Header[$FirstDescriptor + 84] = 1
    [IO.File]::WriteAllBytes($HeaderPath, $Header)

    { Expand-InstallShieldCabinet -Path $HeaderPath -DestinationPath (Join-Path $TestDrive 'cycle') -Name 'split.bin' -CollisionAction Error } |
      Should -Throw '*link chain contains a cycle*'
  }

  It 'builds one analysis context with one extraction, tree walk, and nested MSI parse' {
    $Fixture = Join-Path $TestDrive 'context-setup.exe'
    $Destination = Join-Path $TestDrive 'context-expanded'
    $MsiPath = Join-Path $Destination 'selected.msi'
    [IO.File]::WriteAllBytes($Fixture, [byte[]](0x4D, 0x5A, 0, 0))
    $null = New-Item -Path $Destination -ItemType Directory -Force
    [IO.File]::WriteAllBytes($MsiPath, [byte[]](0))

    InModuleScope InstallShield -Parameters @{ Fixture = $Fixture; Destination = $Destination; MsiPath = $MsiPath } {
      param($Fixture, $Destination, $MsiPath)
      Mock Get-PEOverlayOffset { 0 }
      Mock Invoke-InstallShieldExtractionWithClassicFallback { [pscustomobject]@{ Result = $Destination; Files = @() } }
      Mock Expand-InstallShieldCabinetSupport { [pscustomobject]@{ ExtractedFiles = @(); Warnings = @() } }
      Mock Get-ChildItem { @(Get-Item -LiteralPath $MsiPath) }
      Mock Get-InstallShieldMsiPayloadSelection {
        [pscustomobject]@{ Configuration = $null; SelectedMsiPath = $MsiPath; SelectionSource = 'Test'; Warnings = @() }
      }
      Mock Resolve-InstallShieldMsiFile { Get-Item -LiteralPath $MsiPath }
      Mock Get-MsiInstallerInfo { [pscustomobject]@{ InstallShieldProjectType = 'Basic MSI' } }

      $Context = New-InstallShieldAnalysisContext -Path $Fixture -DestinationPath $Destination

      $Context.Variant | Should -Be 'Basic MSI'
      Should -Invoke Invoke-InstallShieldExtractionWithClassicFallback -Exactly 1
      Should -Invoke Expand-InstallShieldCabinetSupport -Exactly 1
      Should -Invoke Get-ChildItem -Exactly 1
      Should -Invoke Get-InstallShieldMsiPayloadSelection -Exactly 1
      Should -Invoke Get-MsiInstallerInfo -Exactly 1
    }
  }

  It 'parses NB10-prefixed CastleDriver launchers from both architecture payloads' {
    foreach ($Fixture in @(Get-CastleDriverInstallerFixture)) {
      $ExpandedPath = Join-Path $TestDrive "castle-driver-$($Fixture.Architecture)"
      $Info = Get-InstallShieldInfo -Path $Fixture.Path -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.ContainerFormat | Should -Be 'InstallShield Overlay'
      $Info.SelectedMsiPath | Should -Be 'CAS CDC Driver.msi'
      $Info.Warnings | Should -BeNullOrEmpty
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2010'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Overlay/InstallShield'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'MSI/Basic'
      $MsiInfo.DisplayName | Should -Be 'CAS CDC Driver'
      $MsiInfo.DisplayVersion | Should -Be $Fixture.DisplayVersion
      $MsiInfo.ProductCode | Should -Be $Fixture.ProductCode
      $MsiInfo.UpgradeCode | Should -Be $Fixture.UpgradeCode
      $MsiInfo.Scope | Should -Be 'machine'
      $MsiInfo.InstallLocationSwitch | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
    }
  }

  It 'Should parse Advanced UI SuiteId and its exact nested package catalog' {
    $Fixture = Join-Path $Script:FixtureDirectory 'AdvancedUI\SketchUpViewer-2022-0-316-108.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent SketchUp Viewer Advanced UI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.Variant | Should -Be 'Advanced UI'
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2021'
      $Info.InstallShieldRelease.Confidence | Should -Be 'ExactSuiteNamespace'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Suite/AdvancedUI'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Script/aLuZ'
      $Info.ProductCode | Should -Be '{29A129E0-9D13-44AF-A89A-E4CEFB491AF4}'
      $Info.DisplayName | Should -Be 'SketchUp Viewer'
      $Info.DisplayVersion | Should -Be '22.0.316'
      $Info.Publisher | Should -Be 'Trimble, Inc.'
      $Info.Scope | Should -Be 'machine'
      $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\SketchUp\SketchUp Viewer 2022'
      $Info.SuitePackages.Count | Should -Be 2
      $Info.AdvancedUiInfo.Selections.Name | Should -Contain 'SketchUpBase'
      $Info.AdvancedUiInfo.Modes.Name | Should -Be @('Install', 'Maintenance')
      $Info.AdvancedUiInfo.Actions.Type | Should -Contain 'CallInstallScript'
      $Info.AdvancedUiInfo.InstallScriptEntryPoints | Should -Be @('CheckLanguage', 'SetLanguages')
      $Info.InstallScriptInfo.InstallEntryPoints | Should -Be @('CheckLanguage', 'SetLanguages')
      $Info.InstallScriptInfo.SilentSupport | Should -Be 'NotApplicable'
      $Info.InstallScriptInfo.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      $Info.AdvancedUiInfo.Events.Event | Should -Contain 'OnEnd'
      $Info.AdvancedUiInfo.AbortConditions.Condition.Children.Type | Should -Contain 'Any'
      $Info.AdvancedUiInfo.PackageArchitectures | Should -Be @('x64')

      $MsiPackage = $Info.SuitePackages | Where-Object Type -EQ 'Msi'
      $MsiPackage.Files.RelativePath | Should -Be '{3B09BEBD-C840-4818-8020-79198814AD80}\SketchUpViewer.msi'
      $MsiPackage.Operations.Target | Should -Contain 'SketchUpViewer.msi'
      $MsiPackage.HidesNestedArp | Should -BeTrue
      $MsiPackage.TransactionMode | Should -Be 'Disabled'
      $MsiPackage.UpgradeType | Should -Be 'Auto'
      ($MsiPackage.Operations | Where-Object Name -EQ 'Install').ExitBehavior | Should -Be 'DetectIgnore'
      $ExeInstallOperation = ($Info.SuitePackages | Where-Object Type -EQ 'Exe').Operations | Where-Object Name -EQ 'Install'
      $ExeInstallOperation.RebootRequest | Should -Be 'DetectReboot'
      $ExeInstallOperation.RebootCodes | Should -Be @(1641, 3010)
      ($Info.SuitePackages | Where-Object Type -EQ 'Exe').Files.SourceUrl | Should -Match '^http://download\.visualstudio\.microsoft\.com/'
      $Info.Warnings | Should -Not -Contain 'Setup.ini did not identify the MSI; the only extracted MSI is used as a bounded fallback.'

      $NestedPackages = Get-InstallShieldAdvancedUiNestedPackageInfo -Info $Info.AdvancedUiInfo -Architecture x64 -OSVersion 10.0 -BuildNumber 19045 -ProductType Workstation
      $NestedMsi = $NestedPackages | Where-Object PackageType -EQ 'Msi'
      $NestedMsi.Success | Should -BeTrue
      $NestedMsi.Parser | Should -Be 'Windows Installer'
      $NestedMsi.Info.ProductCode | Should -Be '{9FDE1EAA-1ACA-28CD-8077-1E3C45E96033}'
      $NestedExe = $NestedPackages | Where-Object PackageType -EQ 'Exe'
      $NestedExe.SourcePath | Should -Exist
      $NestedExe.SourceUrl | Should -Match '^http://download\.visualstudio\.microsoft\.com/'
      if (Get-Command Get-WinGetInstallerAnalysis -ErrorAction SilentlyContinue) {
        $NestedExe.Success | Should -BeTrue
        $NestedExe.Parser | Should -Be 'WinGet installer analyzer'
      } else {
        $NestedExe.Success | Should -BeFalse
        $NestedExe.Warnings | Should -Match 'Get-WinGetInstallerAnalysis is not loaded'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should parse an official InstallShield prerequisite definition without executing its payload' {
    $PrerequisitePath = Join-Path $Script:FixtureDirectory 'synthetic-dotnet-desktop.prq'
    @'
<SetupPrereq>
  <conditions><condition Type="4" Comparison="2" Path="[ProgramFiles64Folder]\dotnet\shared\Microsoft.WindowsDesktop.App\10.0.5" FileName="PresentationFramework.dll" ReturnValue="" Bits="2" /></conditions>
  <operatingsystemconditions><operatingsystemcondition MajorVersion="10" MinorVersion="0" PlatformId="2" Bits="4" /></operatingsystemconditions>
  <files><file LocalFile="&lt;ISProductFolder&gt;\SetupPrerequisites\windowsdesktop-runtime.exe" URL="https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/10.0.5/windowsdesktop-runtime-10.0.5-win-x64.exe" CheckSum="4416E90423F2A264AF51A2377514138E" FileSize="0,60082160" /></files>
  <execute file="windowsdesktop-runtime.exe" cmdline="/q /norestart" cmdlinesilent="/q /norestart" returncodetoreboot="3010,invalid,1641" />
  <properties Id="{86626E11-C623-42F5-9D63-4EF672544EA9}" Description="Microsoft .NET Desktop Runtime 10.0.5 x64" AltPrqURL="https://example.invalid/runtime.prq" />
  <behavior Reboot="4" />
</SetupPrereq>
'@ | Set-Content -LiteralPath $PrerequisitePath -Encoding utf8
    try {
      $Info = Get-InstallShieldPrerequisiteInfo -Path $PrerequisitePath
      $Info.Id | Should -Be '{86626E11-C623-42F5-9D63-4EF672544EA9}'
      $Info.Files[0].Size | Should -Be 60082160
      $Info.SilentCommandLine | Should -Be '/q /norestart'
      $Info.ReturnCodesToReboot | Should -Be @(3010, 1641)
      $Info.InvalidReturnCodesToReboot | Should -Be 'invalid'
      $Info.DetectionConditions[0].Attributes.FileName | Should -Be 'PresentationFramework.dll'
      $Info.DetectionConditions[0].PredicateKind | Should -Be 'File'
      $Info.DetectionConditions[0].Comparison | Should -Be 'DoesNotExist'
      $Info.DetectionConditions[0].EvidenceKey | Should -Be 'File:[ProgramFiles64Folder]\dotnet\shared\Microsoft.WindowsDesktop.App\10.0.5\PresentationFramework.dll'
      $Info.ShouldInstallState | Should -Be 'Unknown'
      $Info.LimitedUserCompatible | Should -BeFalse
      $Info.RequiresAdministrativePrivileges | Should -BeTrue
      $Info.HasSilentCommandLine | Should -BeTrue

      $TargetInfo = Get-InstallShieldPrerequisiteInfo -Path $PrerequisitePath -ConditionEvidence @{
        'File:[ProgramFiles64Folder]\dotnet\shared\Microsoft.WindowsDesktop.App\10.0.5\PresentationFramework.dll' = $false
      } -Architecture x64 -OSVersion 10.0
      $TargetInfo.DetectionConditionAnalyses[0].State | Should -Be 'True'
      $TargetInfo.OperatingSystemConditionAnalyses[0].State | Should -Be 'True'
      $TargetInfo.ShouldInstallState | Should -Be 'True'
    } finally {
      Remove-Item -LiteralPath $PrerequisitePath -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should distinguish limited-user-compatible prerequisite definitions' {
    $PrerequisitePath = Join-Path $TestDrive 'limited-user.prq'
    @'
<SetupPrereq>
  <execute file="dependency.exe" cmdlinesilent="/quiet" />
  <properties Id="{11111111-1111-1111-1111-111111111111}" Description="Limited-user dependency" />
  <behavior Lua="1" Reboot="2" />
</SetupPrereq>
'@ | Set-Content -LiteralPath $PrerequisitePath -Encoding utf8

    $Info = Get-InstallShieldPrerequisiteInfo -Path $PrerequisitePath

    $Info.LimitedUserCompatible | Should -BeTrue
    $Info.RequiresAdministrativePrivileges | Should -BeFalse
    $Info.HasSilentCommandLine | Should -BeTrue
  }

  It 'Should evaluate typed InstallShield prerequisite comparisons only from supplied evidence' {
    [xml]$Xml = '<conditions><condition Type="32" Comparison="2" Path="HKEY_LOCAL_MACHINE\Software\Vendor\Runtime" FileName="Version" ReturnValue="2.0.0" Bits="2" /></conditions>'
    $Condition = ConvertFrom-InstallShieldPrerequisiteCondition -Node $Xml.DocumentElement.FirstChild

    $Condition.PredicateKind | Should -Be 'RegistryVersion'
    $Condition.Comparison | Should -Be 'LessThan'
    $Condition.RegistryView | Should -Be 'Registry64'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition).State | Should -Be 'Unknown'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition -Evidence @{ $Condition.EvidenceKey = @{ Exists = $true; Version = '1.5.0' } }).State | Should -Be 'True'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition -Evidence @{ $Condition.EvidenceKey = @{ Exists = $true; Version = '2.1.0' } }).State | Should -Be 'False'
    (Resolve-InstallShieldPrerequisiteCondition -Condition $Condition -Evidence @{ $Condition.EvidenceKey = $false }).State | Should -Be 'False'
  }

  It 'Should read ordered setup prerequisite references from Setup.ini' {
    InModuleScope InstallShield {
      $Configuration = ConvertFrom-Ini -Content @'
[ISSetupPrerequisites]
PreReq10=Last.prq
PreReq2=Second.prq
PreReq0=First.prq
'@ -DuplicateKeyAction Last

      $References = @(Get-InstallShieldSetupPrerequisiteReference -Configuration $Configuration)

      $References.Name | Should -Be @('First.prq', 'Second.prq', 'Last.prq')
      $References.Order | Should -Be @(0, 2, 10)
      $References.ReferenceSource | Should -Be @(
        'Setup.ini [ISSetupPrerequisites]',
        'Setup.ini [ISSetupPrerequisites]',
        'Setup.ini [ISSetupPrerequisites]'
      )
    }
  }

  It 'Should require elevation only for direct launcher or selected prerequisite evidence' {
    InModuleScope InstallShield {
      $AdminDefinition = [pscustomobject]@{
        Path                             = 'C:\Extracted\Admin.prq'
        Description                      = 'Administrative dependency'
        RequiresAdministrativePrivileges = $true
        SilentCommandLine                = '/quiet'
      }
      $SelectedEvidence = [pscustomobject]@{
        Reference   = [pscustomobject]@{ Name = 'Admin.prq' }
        Definition  = $AdminDefinition
        MatchMethod = 'ExactIdentityOrName'
      }
      $UnreferencedEvidence = [pscustomobject]@{
        Reference   = $null
        Definition  = $AdminDefinition
        MatchMethod = 'UnreferencedDefinition'
      }

      (Get-InstallShieldElevationInfo -RequestedExecutionLevel asInvoker -PrerequisiteEvidence $SelectedEvidence).ElevationRequirement | Should -Be 'elevationRequired'
      (Get-InstallShieldElevationInfo -RequestedExecutionLevel requireAdministrator).Confidence | Should -Be 'DirectPEManifest'
      (Get-InstallShieldElevationInfo -RequestedExecutionLevel asInvoker -PrerequisiteEvidence $UnreferencedEvidence).ElevationRequirement | Should -BeNullOrEmpty
    }
  }

  It 'Should keep Advanced UI transactions separate from project packages' {
    $SetupXmlPath = Join-Path $Script:FixtureDirectory 'synthetic-suite-transaction.xml'
    @'
<Setup SuiteId="{11111111-1111-1111-1111-111111111111}" xmlns="installshield/2026/bootstrap">
  <ARPInfo><DisplayName>Example Suite</DisplayName><Version>1.0</Version><Publisher>Example</Publisher></ARPInfo>
  <Parcels>
    <Transaction Id="Transaction1"><ParcelRef Id="Package1" /></Transaction>
    <IsmMsi Platform="x64"><UIProperties><Id>Package1</Id><DisplayName>Example MSI Project</DisplayName></UIProperties><Operation Name="Install" Target="setup.exe"><Silent>/s /v/qn</Silent></Operation></IsmMsi>
  </Parcels>
</Setup>
'@ | Set-Content -LiteralPath $SetupXmlPath -Encoding utf8
    try {
      $Info = Get-InstallShieldAdvancedUiInfo -Path $SetupXmlPath
      $Info.Packages.Count | Should -Be 1
      $Info.Packages[0].Type | Should -Be 'IsmMsi'
      $Info.Packages[0].PackageFamily | Should -Be 'InstallShield Basic MSI Project'
      $Info.Transactions.Count | Should -Be 1
      $Info.Transactions[0].ParcelIds | Should -Be @('Package1')
      $Info.CatalogOrder.Kind | Should -Be @('Transaction', 'Package')
    } finally {
      Remove-Item -LiteralPath $SetupXmlPath -Force -ErrorAction SilentlyContinue
    }
  }

  It 'routes the archived InstallShield 5 Professional setup through PackageForTheWeb and old INS' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderArchives\5\IS5pro.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 5 Professional fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 5'
      $Info.InstallShieldProjectType | Should -Be 'InstallScript'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Wrapper/PackageForTheWeb'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Cabinet5/LegacyDescriptor'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Script/INS-Old'
      $Info.InstallShieldCabinetSupport.CatalogEntryCount | Should -Be 451
      $Info.InstallShieldCabinetSupport.MediaVersions.StructuralProfile | Should -Be 'LegacyDescriptorWithoutDigest'
      $Info.InstallScriptInfo.ParserVersionInfo.HeaderKind | Should -Be 'INS-Old'
      $Info.InstallScriptInfo.ParserVersionInfo.InstructionCount | Should -BeGreaterThan 4000
      $Info.InstallScriptInfo.ParserVersionInfo.EmulationTruncated | Should -BeFalse
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should parse early Advanced UI point-release namespaces' {
    $SetupXmlPath = Join-Path $Script:FixtureDirectory 'synthetic-suite-2012.2.xml'
    @'
<Setup SuiteId="{D6E404DB-1F4D-4C22-9417-D5785DDCB365}" xmlns="installshield/2012.2/bootstrap">
  <ARPInfo><DisplayName>InstallShield 2012 Spring</DisplayName><Version>19.00.0000</Version><Publisher>Flexera Software LLC</Publisher></ARPInfo>
  <Mode><Install><When><RegistryValue Key="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D6E404DB-1F4D-4C22-9417-D5785DDCB365}" /></When></Install></Mode>
  <Parcels>
    <Msi ProductCode="{44BA1E0A-99AC-439F-9D97-71F5B92E7E98}" ProductVersion="19.00.0000" Platform="AMD64">
      <UIProperties><Id>Product</Id><DisplayName>InstallShield 2012 Spring MSI</DisplayName></UIProperties>
      <Package><Folder><File Name="payload\InstallShield2012Spring.msi" /></Folder></Package>
      <Operation Name="Install" Target="InstallShield2012Spring.msi"><Silent>ARPSYSTEMCOMPONENT=1 REBOOT=ReallySuppress</Silent></Operation>
    </Msi>
  </Parcels>
</Setup>
'@ | Set-Content -LiteralPath $SetupXmlPath -Encoding utf8
    try {
      $Info = Get-InstallShieldAdvancedUiInfo -Path $SetupXmlPath

      $Info.ReleaseVersion | Should -Be '2012.2'
      $Info.ReleaseYear | Should -Be 2012
      $Info.ProductCode | Should -Be '{D6E404DB-1F4D-4C22-9417-D5785DDCB365}'
      $Info.Scope | Should -Be 'machine'
      $Info.Packages.Count | Should -Be 1
      $Info.Packages[0].Architecture | Should -Be 'x64'
      $Info.Packages[0].Files.RelativePath | Should -Be 'payload\InstallShield2012Spring.msi'
      $Info.Packages[0].HidesNestedArp | Should -BeTrue
    } finally {
      Remove-Item -LiteralPath $SetupXmlPath -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should route the archived 2012 Spring builder through its suite catalog' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderArchives\2012Spring\InstallShield2012SPRPremierComp-full.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 2012 Spring builder fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.Variant | Should -Be 'Advanced UI'
      $Info.InstallShieldProjectType | Should -Be 'Advanced UI'
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2012 Spring'
      $Info.InstallShieldRelease.Confidence | Should -Be 'ExactSuiteNamespace'
      $Info.AdvancedUiInfo.ReleaseVersion | Should -Be '2012.2'
      $Info.ProductCode | Should -Be '{D6E404DB-1F4D-4C22-9417-D5785DDCB365}'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Overlay/ISSetupStream'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Suite/AdvancedUI'
      $Info.Warnings | Should -Not -Contain 'Multiple MSI files were extracted, but Setup.ini did not identify which package the bootstrapper launches.'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should route the archived 2013 builder through the unversioned-year suite namespace' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderArchives\2013\InstallShield2013PremierComp-full.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 2013 builder fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.Variant | Should -Be 'Advanced UI'
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield 2013'
      $Info.InstallShieldRelease.Confidence | Should -Be 'ExactSuiteNamespace'
      $Info.AdvancedUiInfo.ReleaseVersion | Should -Be '2013'
      $Info.ProductCode | Should -Be '{EE4F090B-501A-40AB-82F2-4A4F6F79DC49}'
      $Info.SuitePackages.Count | Should -Be 10
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Suite/AdvancedUI'
      $Info.Warnings | Should -BeNullOrEmpty
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should correlate prerequisite references only by exact source identities' {
    InModuleScope InstallShield {
      $Definitions = @(
        [pscustomobject]@{ Path = 'C:\Extracted\DotNetDesktop.prq'; Id = '{11111111-1111-1111-1111-111111111111}'; Description = '.NET Desktop Runtime' },
        [pscustomobject]@{ Path = 'C:\Extracted\Other.prq'; Id = '{22222222-2222-2222-2222-222222222222}'; Description = 'Other Runtime' }
      )
      $References = @(
        [pscustomobject]@{ Name = 'DotNetDesktop' },
        [pscustomobject]@{ Name = 'Missing Runtime' }
      )

      $Evidence = Join-InstallShieldPrerequisiteEvidence -Reference $References -Definition $Definitions
      ($Evidence | Where-Object { $_.Reference.Name -eq 'DotNetDesktop' }).MatchMethod | Should -Be 'ExactIdentityOrName'
      ($Evidence | Where-Object { $_.Reference.Name -eq 'Missing Runtime' }).MatchMethod | Should -Be 'Unresolved'
      ($Evidence | Where-Object MatchMethod -EQ 'UnreferencedDefinition').Definition.Description | Should -Be 'Other Runtime'
    }
  }

  It 'Should derive elevation from a selected administrative prerequisite in AFAS PCC' {
    $PrerequisiteFixtureDirectory = Join-Path $Script:FixtureDirectory 'PrerequisiteElevation'
    $Fixture = Get-DumplingsTestFixture `
      -Directory $PrerequisiteFixtureDirectory `
      -Name 'AFAS.ProfitCommunicationCenter.7.exe' `
      -Uri 'https://profitdownload.afas.nl/download/PCC/PccSetup7.00.exe' `
      -Sha256 '3AD6CB9756673EF53A6E4B5F50E018D12CDA6D7FCF67359A7A658F04848EEC80'
    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.RequestedExecutionLevel | Should -Be 'asInvoker'
      $Info.ElevationRequirement | Should -Be 'elevationRequired'
      $Info.ElevationRequirementEvidence.Confidence | Should -Be 'SelectedPrerequisiteDefinition'
      $Info.PrerequisiteReferences.Name | Should -Contain 'Microsoft .NET Framework 4.8 Full.prq'
      $Info.ElevationRequirementEvidence.SelectedAdministrativePrerequisites.Count | Should -Be 1
      $Info.ElevationRequirementEvidence.SelectedAdministrativePrerequisites[0].HasSilentCommandLine | Should -BeTrue
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should not infer required elevation from the Vertexshare machine MSI' {
    $PrerequisiteFixtureDirectory = Join-Path $Script:FixtureDirectory 'PrerequisiteElevation'
    $Fixture = Get-DumplingsTestFixture `
      -Directory $PrerequisiteFixtureDirectory `
      -Name 'Vertexshare.WebpConverter.exe' `
      -Uri 'https://vertexshare.com/download/webp-converter/webpconverter-win.exe' `
      -Sha256 '2994524E44CF83735F947E238E233A11A599EFAC63FDA05111BE5DE49DC1610A'
    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.RequestedExecutionLevel | Should -Be 'asInvoker'
      $Info.SelectedMsiInfo.Scope | Should -Be 'machine'
      $Info.SelectedMsiInfo.AllowsInstallWithoutElevation | Should -BeFalse
      $Info.ElevationRequirement | Should -BeNullOrEmpty
      $Info.ElevationRequirementEvidence.Confidence | Should -Be 'Unknown'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should evaluate Advanced UI package eligibility without probing the analysis host' {
    $SetupXmlPath = Join-Path $Script:FixtureDirectory 'synthetic-suite-eligibility.xml'
    @'
<Setup SuiteId="{11111111-1111-1111-1111-111111111111}" xmlns="installshield/2026/bootstrap">
  <ARPInfo><DisplayName>Eligibility Suite</DisplayName><Version>1.0</Version><Publisher>Example</Publisher></ARPInfo>
  <SelectionTree>
    <Selection Name="SupportedWindows" Install="Package1 Package2 Package3"><When><All><Platform OSVersion="10.0-" BuildNumber="19041" ProductType="Workstation" /></All></When></Selection>
  </SelectionTree>
  <Parcels>
    <Msi Platform="x64"><UIProperties><Id>Package1</Id><DisplayName>x64 package</DisplayName></UIProperties><Eligible><When><All><Platform Architecture="x64" /></All></When></Eligible></Msi>
    <Exe><UIProperties><Id>Package2</Id><DisplayName>State-dependent package</DisplayName></UIProperties><Eligible><When><Any><Platform Architecture="x86" /><RegistryExists Key="HKLM\Software\Example" /></Any></When></Eligible></Exe>
    <Exe><UIProperties><Id>Package3</Id><DisplayName>Detection-only package</DisplayName></UIProperties><Detect><When><RegistryExists Key="HKLM\Software\Example" /></When></Detect></Exe>
  </Parcels>
</Setup>
'@ | Set-Content -LiteralPath $SetupXmlPath -Encoding utf8
    try {
      $Info = Get-InstallShieldAdvancedUiInfo -Path $SetupXmlPath
      $Eligibility = Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture x64 -OSVersion 10.0 -BuildNumber 22631 -ProductType Workstation

      ($Eligibility | Where-Object PackageId -EQ 'Package1').State | Should -Be 'True'
      ($Eligibility | Where-Object PackageId -EQ 'Package2').State | Should -Be 'Unknown'
      ($Eligibility | Where-Object PackageId -EQ 'Package2').UnknownPredicates | Should -Contain 'RegistryExists'
      # Detect describes installed state and operation planning, not whether the
      # package can be selected on this target platform.
      ($Eligibility | Where-Object PackageId -EQ 'Package3').State | Should -Be 'True'

      $WrongArchitecture = Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture x86 -OSVersion 10.0 -BuildNumber 22631 -ProductType Workstation
      ($WrongArchitecture | Where-Object PackageId -EQ 'Package1').State | Should -Be 'False'

      $OldWindows = Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture x64 -OSVersion 6.1 -BuildNumber 7601 -ProductType Workstation
      $OldWindows.State | Should -Not -Contain 'True'
      $OldWindows.State | Should -Contain 'False'
    } finally {
      Remove-Item -LiteralPath $SetupXmlPath -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should apply InstallShield None semantics to multi-child Not groups' {
    $Condition = [pscustomobject]@{
      Type       = 'Not'
      Attributes = [ordered]@{}
      Value      = $null
      Children   = @(
        [pscustomobject]@{ Type = 'Platform'; Attributes = [ordered]@{ Architecture = 'x86' }; Value = $null; Children = @() },
        [pscustomobject]@{ Type = 'Platform'; Attributes = [ordered]@{ OSVersion = '-6.1' }; Value = $null; Children = @() }
      )
    }

    (Resolve-InstallShieldSuiteCondition -Condition $Condition -Architecture x64 -OSVersion 10.0).State | Should -Be 'True'
    (Resolve-InstallShieldSuiteCondition -Condition $Condition -Architecture x86 -OSVersion 10.0).State | Should -Be 'False'
  }

  It 'Should identify an official builder-generated InstallScript MSI project' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderDifferential\InstallScriptMSI\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official InstallShield builder fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'InstallScript MSI'
      $Info.InstallShieldProjectTypeEvidence.CustomActions | Should -Contain 'ISVerifyScriptingRuntime'
      $Info.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $Info.HasInstallScript | Should -BeFalse
      $MsiInfo.InstallShieldProjectType | Should -Be 'InstallScript MSI'
      $MsiInfo.DisplayName | Should -Be 'Dumplings InstallScript MSI'
      $MsiInfo.DisplayVersion | Should -Be '1.2.3'
      $MsiInfo.InstallShieldScriptActions.Action | Should -Contain 'ISVerifyScriptingRuntime'
      $MsiInfo.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $MsiInfo.InstallShieldLauncherRequirement.SequenceConditions | Should -Contain 'NOT AFTERREBOOT AND NOT ISSETUPDRIVEN'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'ISVerifyScriptingRuntime').Sequences.Count | Should -BeGreaterThan 0
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should identify the archived InstallShield Developer 8 runtime MSI' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderArchives\8\isscript.msi'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield Developer 8 runtime fixture is unavailable.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.SummaryCreatingApplication | Should -Be 'InstallShield® Developer 8.0'
    $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
    $Info.ProductCode | Should -Be '{790EC520-CCCC-4810-A0FE-061633204CE4}'
    $Info.UpgradeCode | Should -Be '{F90444D7-C81B-41CE-8E5C-2AACA65325E3}'
  }

  It 'Should retain InstallScript MSI classification while analyzing its compiled action' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderDifferential\InstallScriptMSIWithAction\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official scripted InstallScript MSI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = $Info.SelectedMsiInfo

      $Info.Variant | Should -Be 'InstallScript MSI'
      $Info.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $MsiInfo.InstallShieldScriptInfo.EntryPoints | Should -Be 'CreateCboContents'
      $MsiInfo.InstallShieldScriptInfo.Analysis.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Function | Should -Be 'CreateCboContents'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'ISVerifyScriptingRuntime').Kind | Should -Be 'RuntimeVerifier'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover official Basic MSI InstallScript custom actions from Binary.ISSetup.dll' {
    $Fixture = Join-Path $Script:FixtureDirectory 'BuilderDifferential\InstallScriptMSIScripted\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official scripted Basic MSI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = $Info.SelectedMsiInfo

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldProjectType | Should -Be 'Basic MSI'
      $MsiInfo.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldScriptInfo.BinaryName | Should -Be 'ISSetup.dll'
      $MsiInfo.InstallShieldScriptInfo.EntryPoints | Should -Be @(
        'CreateCboContents', 'DllWrapper', 'QueryRegistry', 'ShowRegTestProperty'
      )
      $MsiInfo.InstallShieldScriptInfo.Analysis.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Target | Should -Be 'f1'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Function | Should -Be 'CreateCboContents'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should not misclassify Basic MSI media merely because it carries setup.inx' {
    $Fixture = Join-Path $Script:FixtureDirectory 'PenSoftware_v3_9_2_2_jp_Setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent SHARP Pen Software fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.HasInstallScript | Should -BeTrue
      $Info.Variant | Should -Be 'Basic MSI'
      $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
      $Info.InstallScriptInfo | Should -Not -BeNullOrEmpty
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should retain the legacy extraction command without depending on ISx.exe' {
    Get-ChildItem (Join-Path $PSScriptRoot '..' 'Assets') -Filter 'ISx.exe' -File -Recurse |
      Should -BeNullOrEmpty

    InModuleScope InstallShield {
      Mock Expand-InstallShieldInstaller { 'C:\Extracted\Setup_u' }

      Expand-InstallShield -Path 'C:\Fixtures\Setup.exe' -CollisionAction Rename | Should -Be 'C:\Extracted\Setup_u'
      Should -Invoke Expand-InstallShieldInstaller -Exactly 1 -ParameterFilter {
        $Path -eq 'C:\Fixtures\Setup.exe' -and [string]::IsNullOrEmpty($DestinationPath) -and
        $MaximumExpandedBytes -eq 8GB
      }
    }
  }

  It 'Should distinguish type 3 ISSetupStream attributes with and without timestamps' {
    InModuleScope InstallShield {
      $NameBytes = [Text.Encoding]::Unicode.GetBytes("Setup.inx$([char]0)")
      $Payload = [byte[]](1, 2, 3, 4)
      $Record = [byte[]]::new(24 + 24 + $NameBytes.Length + $Payload.Length)
      [BitConverter]::GetBytes([uint32]$NameBytes.Length).CopyTo($Record, 0)
      [BitConverter]::GetBytes([uint32]6).CopyTo($Record, 4)
      [BitConverter]::GetBytes([uint32]$Payload.Length).CopyTo($Record, 10)
      [BitConverter]::GetBytes([uint16]1).CopyTo($Record, 22)
      for ($Index = 0; $Index -lt 3; $Index++) {
        [BitConverter]::GetBytes(([datetime]'2026-01-02T03:04:05Z').ToFileTimeUtc()).CopyTo($Record, 24 + $Index * 8)
      }
      $NameBytes.CopyTo($Record, 48)
      $Payload.CopyTo($Record, 48 + $NameBytes.Length)

      $Stream = [IO.MemoryStream]::new($Record)
      try {
        $Attribute = Get-InstallShieldStreamAttribute -Stream $Stream -Offset 0 -Type 3

        $Attribute.FileName | Should -Be 'Setup.inx'
        $Attribute.FileLength | Should -Be $Payload.Length
        $Attribute.DataOffset | Should -Be (48 + $NameBytes.Length)
      } finally {
        $Stream.Dispose()
      }

      $RecordWithoutTimestamps = [byte[]]::new(24 + $NameBytes.Length + $Payload.Length)
      [BitConverter]::GetBytes([uint32]$NameBytes.Length).CopyTo($RecordWithoutTimestamps, 0)
      [BitConverter]::GetBytes([uint32]6).CopyTo($RecordWithoutTimestamps, 4)
      [BitConverter]::GetBytes([uint32]$Payload.Length).CopyTo($RecordWithoutTimestamps, 10)
      [BitConverter]::GetBytes([uint16]1).CopyTo($RecordWithoutTimestamps, 22)
      $NameBytes.CopyTo($RecordWithoutTimestamps, 24)
      $Payload.CopyTo($RecordWithoutTimestamps, 24 + $NameBytes.Length)
      $Stream = [IO.MemoryStream]::new($RecordWithoutTimestamps)
      try {
        $Attribute = Get-InstallShieldStreamAttribute -Stream $Stream -Offset 0 -Type 3
        $Attribute.FileName | Should -Be 'Setup.inx'
        $Attribute.DataOffset | Should -Be (24 + $NameBytes.Length)
      } finally {
        $Stream.Dispose()
      }
    }
  }

  It 'Should stream an encoded zlib payload without whole-buffer parser reads' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-streaming'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    $FileName = 'LargePayload.msi'
    $Seed = [Text.Encoding]::UTF8.GetBytes($FileName)
    $Magic = [byte[]](0x13, 0x35, 0x86, 0x07)
    $Expected = [Text.Encoding]::UTF8.GetBytes(('InstallShield streaming regression payload.' * 4096))
    $CompressedStream = [IO.MemoryStream]::new()
    $Compressor = [IO.Compression.ZLibStream]::new($CompressedStream, [IO.Compression.CompressionLevel]::Optimal, $true)
    try {
      $Compressor.Write($Expected, 0, $Expected.Length)
    } finally {
      $Compressor.Dispose()
    }
    $Compressed = $CompressedStream.ToArray()
    $CompressedStream.Dispose()

    $Key = [byte[]]::new($Seed.Length)
    for ($Index = 0; $Index -lt $Seed.Length; $Index++) { $Key[$Index] = $Seed[$Index] -bxor $Magic[$Index % $Magic.Length] }
    $Encoded = [byte[]]::new($Compressed.Length)
    for ($Index = 0; $Index -lt $Compressed.Length; $Index++) {
      $Mixed = ((-bnot $Compressed[$Index]) -band 0xFF) -bxor $Key[($Index % 1024) % $Key.Length]
      $Encoded[$Index] = (($Mixed -shl 4) -bor ($Mixed -shr 4)) -band 0xFF
    }

    try {
      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath; FileName = $FileName; Seed = $Seed; Encoded = $Encoded; Expected = $Expected } {
        $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
        $Stream = [IO.MemoryStream]::new($Encoded)
        try {
          $Attribute = [pscustomobject]@{
            FileName          = $FileName
            Seed              = $Seed
            EncodedFlags      = 6
            FileLength        = $Encoded.Length
            IsUnicodeLauncher = 1
            DataOffset        = 0
          }
          # The record decoder must honor the operation's remaining budget and
          # remove its partial output before a caller retries with a larger one.
          { Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $ExpandedPath `
              -MaximumBytes ($Expected.Length - 1) -StreamMode } | Should -Throw '*limit*'
          Test-Path -LiteralPath (Join-Path $ExpandedPath $FileName) | Should -BeFalse
          $Stream.Position = 0
          $OutputPath = Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $ExpandedPath -StreamMode
          Test-BinarySequence -Left ([IO.File]::ReadAllBytes($OutputPath)) -Right $Expected | Should -BeTrue
        } finally {
          $Stream.Dispose()
        }
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover compiled InstallScript actions from the Tenable Nessus MSI' {
    $Fixture = Join-Path $Script:MsiFixtureDirectory 'Nessus-10.12.3-x64.msi'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent Tenable Nessus MSI fixture is unavailable.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
    $Info.InstallShieldScriptInfo.HasCompiledScript | Should -BeTrue
    $Info.InstallShieldScriptInfo.EntryPoints | Should -Contain 'CheckDirPathPermissions'
    $Info.InstallShieldScriptInfo.EntryPoints | Should -Contain 'SetupProperties'
    $Info.InstallShieldScriptInfo.ExtractedFiles | Should -Contain 'Setup.inx'
    $Info.InstallShieldScriptInfo.ExtractedFiles | Should -Contain 'IsConfig.ini'
    $Info.InstallShieldScriptInfo.Analysis | Should -Not -BeNullOrEmpty
    $Info.Warnings | Should -Not -Match 'Embedded InstallScript custom-action analysis failed'
  }

  It 'Should expose the PackageForTheWeb launch chain without executing it' {
    $Fixture = Join-Path $Script:FixtureDirectory 'U90Ladder_6_6_45.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent U90 Ladder PackageForTheWeb fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.ContainerFormat | Should -Be 'PackageForTheWeb Cabinet'
      $Info.PackageForTheWebInfo.Product | Should -Be 'U90Ladder'
      $Info.PackageForTheWebInfo.NestedSetupPath | Should -Be 'Setup.exe'
      $Info.PackageForTheWebInfo.NestedPayloadPath | Should -Be 'setup.inx'
      $Info.PackageForTheWebInfo.NestedPayloadKind | Should -Be 'InstallScript program'
      $Info.PackageForTheWebInfo.LaunchChain.Stage | Should -Be @('PackageForTheWeb', 'InstallShield setup launcher')
      $Info.PackageForTheWebInfo.LaunchChain[0].Arguments | Should -BeNullOrEmpty
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield Professional 6'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Wrapper/PackageForTheWeb'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Cabinet6/AnsiCatalog'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Script/aLuZ'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the AntRad installer' {
    $Fixture = Get-InstallerFixture -Name 'antrad_setup.exe' -Url 'https://pathloss.com/antrad_setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'antrad-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.SetupIniPath | Should -Be 'Setup.ini'
      $Info.MsiPayloadSelection.SelectionMethod | Should -Be 'SetupIni'
      $Info.MsiPayloadSelection.PackageName | Should -Be 'AntRad.msi'
      $Info.SelectedMsiPath | Should -Be 'AntRad.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'AntRad.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'AntRad'
      $MsiInfo.DisplayVersion | Should -Be '5.01.05'
      $MsiInfo.ProductCode | Should -Be '{9F6A3279-53F2-47C4-8FC8-3149620498EA}'
      $MsiInfo.UpgradeCode | Should -Be '{6767F0A3-5CD9-4B6F-90C4-693DADF557D8}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract the large AVer MSI with bounded memory' -Skip:($env:DUMPLINGS_RUN_LARGE_INSTALLER_TESTS -ne '1') {
    $Archive = Get-InstallerFixture -Name 'AVerTouch.zip' -Url 'https://download.aver.com/AVerTouchWindows/check4Update/AVerTouch.zip' -Sha256 '7E448DF1F753ED22C39DC8F840881622B6CFB294CDB071138D911481F19C51EC'
    $Fixture = Join-Path $Script:FixtureDirectory 'AVerTouchQt.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'aver-touch-expanded'
    $FixtureHash = '2D9C3D01E3284893DA78BF3FD633E699BD71747959B2F37253645D3C9D97252C'

    if (-not (Test-Path -LiteralPath $Fixture) -or (Get-DumplingsTestFixtureHash -Path $Fixture) -ne $FixtureHash) {
      $Zip = [IO.Compression.ZipFile]::OpenRead($Archive)
      try {
        $Entry = $Zip.GetEntry('AVerTouchQt.exe')
        if (-not $Entry) { throw 'The AVer archive does not contain AVerTouchQt.exe.' }
        $InputStream = $Entry.Open()
        $OutputStream = [IO.File]::Create($Fixture)
        try { $InputStream.CopyTo($OutputStream) } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
      } finally {
        $Zip.Dispose()
      }
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be $FixtureHash

    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.SelectedMsiPath | Should -Be 'AVerTouch.msi'
      (Get-Item -LiteralPath $MsiInfo.Path).Length | Should -Be 435532288
      $MsiInfo.PackageArchitecture | Should -Be 'x86'
      $MsiInfo.DisplayVersion | Should -Be '1.3.2114.0'
      $MsiInfo.ProductCode | Should -Be '{B16D6CCE-CC0A-4516-8BA8-897E24376A2B}'
      $MsiInfo.UpgradeCode | Should -Be '{2525391D-961E-42A8-B163-22226CAFB2CB}'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the Tachograph File Viewer installer' {
    $Fixture = Get-InstallerFixture -Name 'TachoFileViewer_3_40.exe' -Url 'https://www.prosysdev.com/downloads/TachoFileViewer_3_40.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'tachograph-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.PackageName | Should -Be 'Tachograph File Viewer.msi'
      $Info.SelectedMsiPath | Should -Be 'Tachograph File Viewer.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'Tachograph File Viewer.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'Tachograph File Viewer'
      $MsiInfo.DisplayVersion | Should -Be '3.40'
      $MsiInfo.ProductCode | Should -Be '{AAA4DC80-8FA6-4A8E-AFD2-D82B9CCCA2A8}'
      $MsiInfo.UpgradeCode | Should -Be '{F97E4ADC-C4FE-4253-B342-EC2D8873E27B}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the WiFi Sensor Software installer' {
    $Fixture = Get-InstallerFixture -Name 'WiFi Sensor Software.exe' -Url 'https://s3.amazonaws.com/easylogcloud/WiFi%20Sensor%20Software.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'wifi-sensor-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.PackageName | Should -Be 'WiFi Sensor Software.msi'
      $Info.SelectedMsiPath | Should -Be 'WiFi Sensor Software.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'WiFi Sensor Software.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'WiFi Sensor Software'
      $MsiInfo.DisplayVersion | Should -Be '1.40.15'
      $MsiInfo.ProductCode | Should -Be '{EF49368B-13B1-4F5B-B453-83C725D31F82}'
      $MsiInfo.UpgradeCode | Should -Be '{60BF28CD-D862-47B9-A3C1-A361DB53CF77}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should select the Setup.ini MSI instead of the first wildcard match' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-selection'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $null = New-Item -Path (Join-Path $ExpandedPath 'payload') -ItemType Directory -Force
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'First.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'payload\Selected.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllText((Join-Path $ExpandedPath 'Setup.ini'), @'
[Startup]
PackageName=Selected.msi

[Selected.msi]
Type=1
Location=payload\Selected.msi
'@)

      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath } {
        $MsiFiles = @(Get-ChildItem -LiteralPath $ExpandedPath -Filter '*.msi' -Recurse -File)
        $Selection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExpandedPath -MsiFile $MsiFiles
        $Installer = [pscustomobject]@{
          ExtractedPath       = $ExpandedPath
          MsiPayloadSelection = $Selection
        }
        $Selected = Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false

        $Selection.SelectionMethod | Should -Be 'SetupIni'
        $Selection.SelectedMsiPath | Should -Be 'payload\Selected.msi'
        $Selected.Name | Should -Be 'Selected.msi'
        { Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern 'First.msi' -NameWasSpecified $true } | Should -Throw '*does not match the requested pattern*'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should follow an InstallShield 11.5 external-media Setup.ini without scanning sibling files' {
    $FixtureRoot = Join-Path $Script:FixtureDirectory 'BuilderDifferential\Legacy115\BuilderInstaller'
    $Fixture = Join-Path $FixtureRoot 'setup.exe'
    $MsiFixture = Join-Path $FixtureRoot 'InstallShield1150.msi'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf) -or
      -not (Test-Path -LiteralPath $MsiFixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 11.5 external-media fixture is unavailable.'
      return
    }

    $ExpandedPath = Join-Path $Script:FixtureDirectory 'installshield-115-external-expanded'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.SourceKind | Should -Be 'ExternalSibling'
      $Info.SetupIniPath | Should -Be 'Setup.ini'
      $Info.SelectedMsiPath | Should -Be 'InstallShield1150.msi'
      $Info.MsiFiles | Should -Contain (Get-Item -LiteralPath $MsiFixture).FullName
      $MsiInfo.Path | Should -Be (Get-Item -LiteralPath $MsiFixture).FullName
      $MsiInfo.DisplayName | Should -Be 'InstallShield 11.5'
      $MsiInfo.DisplayVersion | Should -Be '11.50.0000'
      $MsiInfo.ProductCode | Should -Be '{97033B64-7CE1-428F-BD7F-101D26C9AF9E}'
      $MsiInfo.UpgradeCode | Should -Be '{474F074C-7A6F-45A7-9550-8D5ECE5938DE}'
      $MsiInfo.InstallShieldProjectType | Should -Be 'Basic MSI'
      $Info.InstallShieldRelease.ProductVersion | Should -Be '11.5'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'MSI/Basic'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should not substitute an unrelated sibling MSI for a missing Setup.ini package' {
    $MediaRoot = Join-Path $TestDrive 'external-media-missing-package'
    $ExpandedPath = Join-Path $TestDrive 'external-media-missing-package-expanded'
    $null = New-Item -Path $MediaRoot -ItemType Directory -Force
    $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
    [IO.File]::WriteAllBytes((Join-Path $MediaRoot 'setup.exe'), [byte[]]@(0x4D, 0x5A))
    [IO.File]::WriteAllBytes((Join-Path $MediaRoot 'Unrelated.msi'), [byte[]]@(0))
    [IO.File]::WriteAllText((Join-Path $MediaRoot 'Setup.ini'), @'
[Startup]
PackageName=Missing.msi

[Missing.msi]
Location=payload\Missing.msi
'@)

    InModuleScope InstallShield -Parameters @{ MediaRoot = $MediaRoot; ExpandedPath = $ExpandedPath } {
      $Selection = Get-InstallShieldExternalMediaSelection `
        -InstallerPath (Join-Path $MediaRoot 'setup.exe') -ExtractedPath $ExpandedPath

      $Selection.SelectionMethod | Should -Be 'SetupIniUnresolved'
      $Selection.SourceKind | Should -Be 'ExternalOrMissing'
      $Selection.SelectedMsiPath | Should -BeNullOrEmpty
      $Selection.Warnings | Should -Contain "Setup.ini selects 'Missing.msi', but that MSI path was not extracted."
    }
  }

  It 'Should reject an unresolved multi-MSI payload without an explicit override' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-ambiguous'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'First.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'Second.msi'), [byte[]]@(0))

      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath } {
        $MsiFiles = @(Get-ChildItem -LiteralPath $ExpandedPath -Filter '*.msi' -File)
        $Selection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExpandedPath -MsiFile $MsiFiles
        $Installer = [pscustomobject]@{
          ExtractedPath       = $ExpandedPath
          MsiPayloadSelection = $Selection
        }

        $Selection.SelectionMethod | Should -Be 'Unresolved'
        $Selection.SelectedMsiPath | Should -BeNullOrEmpty
        { Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false } | Should -Throw '*selection is ambiguous*'
        (Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern 'Second.msi' -NameWasSpecified $true).Name | Should -Be 'Second.msi'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
