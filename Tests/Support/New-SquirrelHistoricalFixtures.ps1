# SPDX-License-Identifier: Apache-2.0
#Requires -Version 7.4

<#
.SYNOPSIS
  Build application-complete historical Squirrel and Clowd.Squirrel setup fixtures.
.DESCRIPTION
  Downloads hash-pinned upstream packages, combines their committed application
  payloads with the matching historical setup launchers, and writes the exact
  DATA resources used by Squirrel.Windows 1.9.1 and Clowd.Squirrel 2.7.98-pre.
  No installer or vendor builder executable is launched.
.PARAMETER FixtureRoot
  Durable Dumplings-TestFixtures root that receives Sources and Builders files.
#>
[CmdletBinding()]
param (
  [Parameter(Mandatory)][string]$FixtureRoot
)

$FixtureRoot = [IO.Path]::GetFullPath($FixtureRoot)
$SourceRoot = Join-Path $FixtureRoot 'Sources\SquirrelHistoricalFixtures'
$BuilderRoot = Join-Path $FixtureRoot 'Builders\Squirrel'
$FixedTimestamp = [DateTimeOffset]::Parse('2020-01-01T00:00:00Z', [Globalization.CultureInfo]::InvariantCulture)

function Get-VerifiedSquirrelFixtureSource {
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$Sha256
  )

  $Path = [IO.Path]::GetFullPath($Path)
  $RootPrefix = $SourceRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if (-not $Path.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Source path escapes the fixture source root: $Path" }
  $Parent = [IO.Path]::GetDirectoryName($Path)
  $null = New-Item -ItemType Directory -Path $Parent -Force
  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    $ActualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($ActualHash -ceq $Sha256.ToUpperInvariant()) { return $Path }
  }

  $PartialPath = "$Path.partial-$PID-$([Guid]::NewGuid().ToString('N'))"
  try {
    Invoke-WebRequest -Uri $Uri -OutFile $PartialPath
    $ActualHash = (Get-FileHash -LiteralPath $PartialPath -Algorithm SHA256).Hash
    if ($ActualHash -cne $Sha256.ToUpperInvariant()) { throw "Source hash mismatch for $Uri. Expected $Sha256, received $ActualHash." }
    Move-Item -LiteralPath $PartialPath -Destination $Path -Force
  } finally {
    Remove-Item -LiteralPath $PartialPath -Force -ErrorAction SilentlyContinue
  }
  return $Path
}

function Read-SquirrelFixtureZipEntry {
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$EntryName,
    [ValidateRange(1, 268435456)][long]$MaximumBytes = 67108864
  )

  $Archive = [IO.Compression.ZipFile]::OpenRead($Path)
  try {
    $Entries = @($Archive.Entries | Where-Object { [string]::Equals($_.FullName, $EntryName, [StringComparison]::Ordinal) })
    if ($Entries.Count -ne 1) { throw "Expected exactly one '$EntryName' entry in $Path." }
    $Entry = $Entries[0]
    if ($Entry.Length -le 0 -or $Entry.Length -gt $MaximumBytes) { throw "ZIP entry '$EntryName' has an invalid or excessive size." }
    $EntryInputStream = $Entry.Open()
    $Output = [IO.MemoryStream]::new([int]$Entry.Length)
    try {
      $EntryInputStream.CopyTo($Output)
      if ($Output.Length -ne $Entry.Length) { throw "ZIP entry '$EntryName' did not expand to its declared length." }
      return $Output.ToArray()
    } finally {
      $Output.Dispose()
      $EntryInputStream.Dispose()
    }
  } finally {
    $Archive.Dispose()
  }
}

function New-SquirrelFixtureZip {
  [CmdletBinding(SupportsShouldProcess)]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][Collections.Specialized.OrderedDictionary]$Entry
  )

  if (-not $PSCmdlet.ShouldProcess($Path, 'Create deterministic fixture ZIP')) { return }
  $Output = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  $Archive = [IO.Compression.ZipArchive]::new($Output, [IO.Compression.ZipArchiveMode]::Create, $false)
  try {
    foreach ($Item in $Entry.GetEnumerator()) {
      $ArchiveEntry = $Archive.CreateEntry([string]$Item.Key, [IO.Compression.CompressionLevel]::Optimal)
      $ArchiveEntry.LastWriteTime = $FixedTimestamp
      $EntryStream = $ArchiveEntry.Open()
      try {
        $Bytes = [byte[]]$Item.Value
        $EntryStream.Write($Bytes, 0, $Bytes.Length)
      } finally {
        $EntryStream.Dispose()
      }
    }
  } finally {
    $Archive.Dispose()
  }
}

if (-not ('Dumplings.Tests.SquirrelFixtureResourceWriter' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Dumplings.Tests
{
    public sealed class SquirrelFixtureResource
    {
        public string Type { get; set; }
        public ushort Id { get; set; }
        public ushort Language { get; set; }
        public byte[] Data { get; set; }
    }

    public static class SquirrelFixtureResourceWriter
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr BeginUpdateResourceW(string fileName, bool deleteExistingResources);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool UpdateResourceW(IntPtr update, string type, IntPtr name, ushort language, byte[] data, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool EndUpdateResourceW(IntPtr update, bool discard);

        public static void Write(string path, SquirrelFixtureResource[] resources)
        {
            IntPtr update = BeginUpdateResourceW(path, false);
            if (update == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            bool discard = true;
            try {
                foreach (SquirrelFixtureResource resource in resources) {
                    if (resource == null || String.IsNullOrEmpty(resource.Type) || resource.Data == null || resource.Data.Length == 0)
                        throw new ArgumentException("Resource entries must contain a type, identifier, language, and data.");
                    if (!UpdateResourceW(update, resource.Type, new IntPtr(resource.Id), resource.Language, resource.Data, checked((uint) resource.Data.Length)))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                discard = false;
            } finally {
                if (!EndUpdateResourceW(update, discard) && !discard)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
'@
}

function ConvertTo-SquirrelFixtureResource {
  param (
    [Parameter(Mandatory)][string]$Type,
    [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Id,
    [Parameter(Mandatory)][byte[]]$Data,
    [ValidateRange(0, 65535)][int]$Language = 0x0409
  )

  $Resource = [Dumplings.Tests.SquirrelFixtureResource]::new()
  $Resource.Type = $Type
  $Resource.Id = [uint16]$Id
  $Resource.Language = [uint16]$Language
  $Resource.Data = $Data
  return $Resource
}

function Write-SquirrelFixtureProvenance {
  [CmdletBinding(SupportsShouldProcess)]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Format,
    [Parameter(Mandatory)][object[]]$Source
  )

  if (-not $PSCmdlet.ShouldProcess("$Path.provenance.json", 'Write fixture provenance')) { return }
  $File = Get-Item -LiteralPath $Path
  [ordered]@{
    Format       = $Format
    Output       = $File.Name
    Length       = $File.Length
    Sha256       = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
    Sources      = $Source
    Construction = 'Static ZIP composition and Win32 UpdateResourceW; no installer or vendor builder executable was launched.'
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Path.provenance.json" -Encoding utf8NoBOM
}

$SquirrelPackageUri = [uri]'https://api.nuget.org/v3-flatcontainer/squirrel.windows/1.9.1/squirrel.windows.1.9.1.nupkg'
$SquirrelPackageHash = 'A79F77C5927CAACF24890222381B8DF094A621CD997328F573F53CB17F5654DF'
$SquirrelPackage = Get-VerifiedSquirrelFixtureSource -Uri $SquirrelPackageUri -Path (Join-Path $SourceRoot 'Squirrel.Windows\1.9.1\squirrel.windows.1.9.1.nupkg') -Sha256 $SquirrelPackageHash
$SquirrelAppUri = [uri]'https://raw.githubusercontent.com/Squirrel/Squirrel.Windows/c1e8987e2a42c7124600a79b7592d67fbd488969/test/fixtures/ProjectWithContent.1.0.0.0-beta-full.nupkg'
$SquirrelAppHash = 'F6B605F85A46A02C4BFF314C100DFAB02F05986D04F5FBCFDD8EDA6A5EEB86B0'
$SquirrelApp = Get-VerifiedSquirrelFixtureSource -Uri $SquirrelAppUri -Path (Join-Path $SourceRoot 'Squirrel.Windows\1.9.1\ProjectWithContent.1.0.0.0-beta-full.nupkg') -Sha256 $SquirrelAppHash

$SquirrelSetup = Read-SquirrelFixtureZipEntry -Path $SquirrelPackage -EntryName 'tools/Setup.exe'
$SquirrelUpdater = Read-SquirrelFixtureZipEntry -Path $SquirrelPackage -EntryName 'tools/Squirrel.exe'
$SquirrelAppBytes = [IO.File]::ReadAllBytes($SquirrelApp)
$SquirrelReleaseName = 'ProjectWithContent-1.0.0.0-beta-full.nupkg'
$Sha1 = [Security.Cryptography.SHA1]::Create()
try { $SquirrelReleaseHash = [Convert]::ToHexString($Sha1.ComputeHash($SquirrelAppBytes)).ToLowerInvariant() } finally { $Sha1.Dispose() }
$SquirrelReleaseText = "$SquirrelReleaseHash $SquirrelReleaseName $($SquirrelAppBytes.Length)`n"
$SquirrelOuterZip = [IO.Path]::GetTempFileName()
try {
  New-SquirrelFixtureZip -Path $SquirrelOuterZip -Entry ([ordered]@{
      'Update.exe'         = $SquirrelUpdater
      $SquirrelReleaseName = $SquirrelAppBytes
      'RELEASES'           = [Text.UTF8Encoding]::new($false).GetBytes($SquirrelReleaseText)
    })
  $SquirrelOutput = Join-Path $BuilderRoot 'Squirrel.Windows\1.9.1\ProjectWithContent-1.0.0.0-beta-Setup.exe'
  $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($SquirrelOutput)) -Force
  [IO.File]::WriteAllBytes($SquirrelOutput, $SquirrelSetup)
  [Dumplings.Tests.SquirrelFixtureResourceWriter]::Write($SquirrelOutput, @(
      ConvertTo-SquirrelFixtureResource -Type 'DATA' -Id 131 -Data ([IO.File]::ReadAllBytes($SquirrelOuterZip))
    ))
  Write-SquirrelFixtureProvenance -Path $SquirrelOutput -Format 'Squirrel.Windows 1.9.1 DATA/#131 setup ZIP' -Source @(
    [ordered]@{ Uri = $SquirrelPackageUri.AbsoluteUri; Sha256 = $SquirrelPackageHash; Entries = @('tools/Setup.exe', 'tools/Squirrel.exe') }
    [ordered]@{ Uri = $SquirrelAppUri.AbsoluteUri; Sha256 = $SquirrelAppHash; EntryName = $SquirrelReleaseName }
  )
} finally {
  Remove-Item -LiteralPath $SquirrelOuterZip -Force -ErrorAction SilentlyContinue
}

$ClowdPackageUri = [uri]'https://api.nuget.org/v3-flatcontainer/clowd.squirrel/2.7.98-pre/clowd.squirrel.2.7.98-pre.nupkg'
$ClowdPackageHash = 'A0B4A52193A5ED6CBEC735AAEBD60B92C7C5659902F628D231AEA71AD5094AFC'
$ClowdPackage = Get-VerifiedSquirrelFixtureSource -Uri $ClowdPackageUri -Path (Join-Path $SourceRoot 'Clowd.Squirrel\2.7.98-pre\clowd.squirrel.2.7.98-pre.nupkg') -Sha256 $ClowdPackageHash
$ClowdAppUri = [uri]'https://raw.githubusercontent.com/velopack/velopack/a482c69222932068ab2da0b003892e68b3622b1a/test/fixtures/Clowd-3.4.287-full.nupkg'
$ClowdAppHash = '924C2CA7D8F9C28D979D51261F0C5B50DC54213D9D36F9BB78E69370C4B16DA4'
$ClowdApp = Get-VerifiedSquirrelFixtureSource -Uri $ClowdAppUri -Path (Join-Path $SourceRoot 'Clowd.Squirrel\2.7.98-pre\Clowd-3.4.287-full.nupkg') -Sha256 $ClowdAppHash

$ClowdSetup = Read-SquirrelFixtureZipEntry -Path $ClowdPackage -EntryName 'tools/Setup.exe'
$ClowdAppBytes = [IO.File]::ReadAllBytes($ClowdApp)
$Utf16 = [Text.Encoding]::Unicode
$ClowdOutput = Join-Path $BuilderRoot 'Clowd.Squirrel\2.7.98-pre\Clowd-3.4.287-Setup.exe'
$null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($ClowdOutput)) -Force
[IO.File]::WriteAllBytes($ClowdOutput, $ClowdSetup)
[Dumplings.Tests.SquirrelFixtureResourceWriter]::Write($ClowdOutput, @(
    ConvertTo-SquirrelFixtureResource -Type 'DATA' -Id 200 -Data $Utf16.GetBytes("Clowd`0`0")
    ConvertTo-SquirrelFixtureResource -Type 'DATA' -Id 201 -Data $Utf16.GetBytes("Clowd`0`0")
    ConvertTo-SquirrelFixtureResource -Type 'DATA' -Id 203 -Data $Utf16.GetBytes("net6.0.2-x64`0`0")
    ConvertTo-SquirrelFixtureResource -Type 'DATA' -Id 204 -Data $Utf16.GetBytes("Clowd-3.4.287-full.nupkg`0`0")
    ConvertTo-SquirrelFixtureResource -Type 'DATA' -Id 205 -Data $ClowdAppBytes
  ))
Write-SquirrelFixtureProvenance -Path $ClowdOutput -Format 'Clowd.Squirrel 2.7.98-pre DATA/#200-205 package setup' -Source @(
  [ordered]@{ Uri = $ClowdPackageUri.AbsoluteUri; Sha256 = $ClowdPackageHash; Entries = @('tools/Setup.exe') }
  [ordered]@{ Uri = $ClowdAppUri.AbsoluteUri; Sha256 = $ClowdAppHash; Resource = 'DATA/#205' }
)

@(
  Get-Item -LiteralPath $SquirrelOutput
  Get-Item -LiteralPath $ClowdOutput
) | Select-Object FullName, Length, @{ Name = 'Sha256'; Expression = { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } }
