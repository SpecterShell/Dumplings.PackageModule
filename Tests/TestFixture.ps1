# SPDX-License-Identifier: MIT

if (-not $Script:DumplingsTestFixtureHashCache) { $Script:DumplingsTestFixtureHashCache = @{} }

function Get-DumplingsTestFixtureHash {
  param([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path
  $CacheKey = $File.FullName
  $Cached = $Script:DumplingsTestFixtureHashCache[$CacheKey]
  if ($Cached -and $Cached.Length -eq $File.Length -and $Cached.LastWriteTimeUtcTicks -eq $File.LastWriteTimeUtc.Ticks) {
    return $Cached.Sha256
  }
  $Sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
  $Script:DumplingsTestFixtureHashCache[$CacheKey] = [pscustomobject]@{
    Length                = $File.Length
    LastWriteTimeUtcTicks = $File.LastWriteTimeUtc.Ticks
    Sha256                = $Sha256
  }
  return $Sha256
}

function Get-DumplingsTestFixtureRoot {
  <#
  .SYNOPSIS
    Return the durable installer fixture cache outside the Dumplings checkout.
  #>
  if ($env:DUMPLINGS_TEST_FIXTURE_ROOT) {
    return [IO.Path]::GetFullPath($env:DUMPLINGS_TEST_FIXTURE_ROOT)
  }
  $RepositoryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..'))
  return Join-Path $RepositoryDirectory 'Dumplings-TestFixtures'
}

function Get-DumplingsTestFixtureDirectory {
  <#
  .SYNOPSIS
    Create and return one suite-specific durable fixture directory.
  #>
  param([Parameter(Mandatory)][string]$Name)

  $Root = Get-DumplingsTestFixtureRoot
  $Directory = [IO.Path]::GetFullPath((Join-Path $Root $Name))
  $RootPrefix = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if (-not $Directory.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Fixture directory escapes the cache root: $Name"
  }
  $null = New-Item -Path $Directory -ItemType Directory -Force
  return $Directory
}

function Write-DumplingsTestFixtureCacheRecord {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Uri
  )

  $File = Get-Item -LiteralPath $Path
  $MetadataPath = "$Path.fixture.json"
  $PartialMetadataPath = "$MetadataPath.partial"
  [ordered]@{
    Uri         = $Uri
    Length      = $File.Length
    Sha256      = Get-DumplingsTestFixtureHash -Path $Path
    CachedAtUtc = [DateTime]::UtcNow.ToString('o')
  } | ConvertTo-Json | Set-Content -LiteralPath $PartialMetadataPath -Encoding UTF8
  Move-Item -LiteralPath $PartialMetadataPath -Destination $MetadataPath -Force
}

function Test-DumplingsTestFixtureCacheEntry {
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$Sha256
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  $File = Get-Item -LiteralPath $Path
  if ($File.Length -le 0) { return $false }

  $ActualHash = Get-DumplingsTestFixtureHash -Path $Path
  if ($Sha256 -and $ActualHash -ne $Sha256) { return $false }

  $MetadataPath = "$Path.fixture.json"
  if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf)) { return $true }
  try {
    $Metadata = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
    return [int64]$Metadata.Length -eq $File.Length -and [string]$Metadata.Sha256 -eq $ActualHash
  } catch {
    return $false
  }
}

function Get-DumplingsTestFixture {
  <#
  .SYNOPSIS
    Download a test fixture atomically and retain verified cache metadata.
  .PARAMETER UseSourceForgeMetaRefresh
    Resolve SourceForge's HTML meta-refresh target before downloading.
  #>
  param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][Alias('Url')][uri]$Uri,
    [string]$Sha256,
    [hashtable]$Headers,
    [string]$UserAgent,
    [switch]$UseSourceForgeMetaRefresh
  )

  $Directory = [IO.Path]::GetFullPath($Directory)
  $Path = [IO.Path]::GetFullPath((Join-Path $Directory $Name))
  $DirectoryPrefix = $Directory.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if (-not $Path.StartsWith($DirectoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Fixture name escapes its cache directory: $Name"
  }
  $null = New-Item -Path $Directory -ItemType Directory -Force

  $NameBytes = [Text.Encoding]::UTF8.GetBytes($Path.ToLowerInvariant())
  $HashAlgorithm = [Security.Cryptography.SHA256]::Create()
  try { $LockHash = [Convert]::ToHexString($HashAlgorithm.ComputeHash($NameBytes)) } finally { $HashAlgorithm.Dispose() }
  $Mutex = [Threading.Mutex]::new($false, "DumplingsTestFixture-$LockHash")
  $HasLock = $false
  try {
    try { $HasLock = $Mutex.WaitOne([TimeSpan]::FromMinutes(10)) } catch [Threading.AbandonedMutexException] { $HasLock = $true }
    if (-not $HasLock) { throw "Timed out waiting for the fixture cache lock: $Path" }

    if (Test-DumplingsTestFixtureCacheEntry -Path $Path -Sha256 $Sha256) {
      if (-not (Test-Path -LiteralPath "$Path.fixture.json")) {
        Write-DumplingsTestFixtureCacheRecord -Path $Path -Uri $Uri.AbsoluteUri
      }
      return $Path
    }

    Remove-Item -LiteralPath $Path, "$Path.fixture.json" -Force -ErrorAction SilentlyContinue
    $ResolvedUri = $Uri
    if ($UseSourceForgeMetaRefresh) {
      $PageRequest = @{ Uri = $ResolvedUri }
      if ($Headers) { $PageRequest.Headers = $Headers }
      if ($UserAgent) { $PageRequest.UserAgent = $UserAgent }
      $Page = Invoke-WebRequest @PageRequest
      $MetaRefresh = [regex]::Match($Page.Content, 'url=([^"&]+(?:&amp;[^"<]+)*)')
      if (-not $MetaRefresh.Success) { throw "Failed to resolve the SourceForge download URL for $Uri" }
      $ResolvedUri = [uri][Net.WebUtility]::HtmlDecode($MetaRefresh.Groups[1].Value)
    }

    $PartialPath = "$Path.partial-$PID-$([Guid]::NewGuid().ToString('N'))"
    try {
      $Request = @{ Uri = $ResolvedUri; OutFile = $PartialPath }
      if ($Headers) { $Request.Headers = $Headers }
      if ($UserAgent) { $Request.UserAgent = $UserAgent }
      Invoke-WebRequest @Request
      if (-not (Test-DumplingsTestFixtureCacheEntry -Path $PartialPath -Sha256 $Sha256)) {
        throw "The downloaded fixture is empty or does not match its expected SHA-256: $ResolvedUri"
      }
      Move-Item -LiteralPath $PartialPath -Destination $Path -Force
      Write-DumplingsTestFixtureCacheRecord -Path $Path -Uri $ResolvedUri.AbsoluteUri
    } finally {
      Remove-Item -LiteralPath $PartialPath -Force -ErrorAction SilentlyContinue
    }
    return $Path
  } finally {
    if ($HasLock) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}
