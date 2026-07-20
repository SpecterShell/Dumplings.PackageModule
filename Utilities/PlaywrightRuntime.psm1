# SPDX-License-Identifier: Apache-2.0

# Package sources:
# https://github.com/Kaliiiiiiiiii-Vinyzu/patchright
# https://github.com/DevEnterpriseSoftware/patchright-dotnet

# Patchright is API-compatible with Microsoft.Playwright but couples the shared
# Microsoft.Playwright.dll identity to its patched JavaScript driver. This utility
# installs only that assembly, Windows Node executable, and driver into a cache.

function Get-DumplingsPlaywrightRuntimeLock {
  <#
  .SYNOPSIS
    Read the pinned Playwright runtime metadata.
  .PARAMETER LockPath
    Path to the PowerShell data file containing the package version, URL, and hash.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$LockPath
  )

  $Lock = Import-PowerShellDataFile -LiteralPath $LockPath
  foreach ($RequiredKey in 'RuntimeId', 'Version', 'PackageUri', 'PackageSha256') {
    if ([string]::IsNullOrWhiteSpace([string]$Lock[$RequiredKey])) {
      throw "The Playwright runtime lock is missing '${RequiredKey}': ${LockPath}"
    }
  }
  return $Lock
}

function Get-DumplingsPlaywrightRuntimePath {
  <#
  .SYNOPSIS
    Resolve the version-specific Playwright runtime directory.
  .PARAMETER CachePath
    Parent directory that stores versioned Playwright runtimes.
  .PARAMETER Version
    Pinned browser automation package version.
  .PARAMETER RuntimeId
    Stable provider name used to avoid cache collisions with stock Playwright.
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [string]$CachePath,

    [Parameter(Mandatory)]
    [string]$Version,

    [Parameter(Mandatory)]
    [string]$RuntimeId
  )

  if ([string]::IsNullOrWhiteSpace($CachePath)) {
    if (-not [string]::IsNullOrWhiteSpace($env:DUMPLINGS_PLAYWRIGHT_RUNTIME_PATH)) {
      return [IO.Path]::GetFullPath($env:DUMPLINGS_PLAYWRIGHT_RUNTIME_PATH)
    }
    $CacheRoot = $env:LOCALAPPDATA ?? [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $CachePath = Join-Path $CacheRoot 'Dumplings' 'Playwright'
  }
  return [IO.Path]::GetFullPath((Join-Path $CachePath "${RuntimeId}-${Version}"))
}

function Test-DumplingsPlaywrightRuntime {
  <#
  .SYNOPSIS
    Verify that the cached runtime contains the assembly and coupled driver files.
  .PARAMETER Path
    Version-specific Playwright runtime directory.
  .PARAMETER Version
    Expected Microsoft.Playwright assembly version prefix.
  #>
  [CmdletBinding()]
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [string]$Version
  )

  $AssemblyPath = Join-Path $Path 'Microsoft.Playwright.dll'
  $NodePath = Join-Path $Path '.playwright' 'node' 'win32_x64' 'node.exe'
  $NodeLicensePath = Join-Path $Path '.playwright' 'node' 'LICENSE'
  $DriverPath = Join-Path $Path '.playwright' 'package' 'cli.js'
  $DriverLicensePath = Join-Path $Path '.playwright' 'package' 'LICENSE'
  if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $NodePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $NodeLicensePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $DriverPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $DriverLicensePath -PathType Leaf)) {
    return $false
  }

  try {
    $AssemblyVersion = [Reflection.AssemblyName]::GetAssemblyName($AssemblyPath).Version
    return $AssemblyVersion -and $AssemblyVersion.ToString().StartsWith($Version + '.', [StringComparison]::Ordinal)
  } catch {
    return $false
  }
}

function Save-DumplingsPlaywrightRuntime {
  <#
  .SYNOPSIS
    Download and extract the pinned Windows Playwright runtime atomically.
  .PARAMETER Lock
    Runtime lock returned by Get-DumplingsPlaywrightRuntimeLock.
  .PARAMETER DestinationPath
    Version-specific destination directory.
  .PARAMETER MaximumRetryCount
    Number of download attempts before failing.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Lock,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 3
  )

  $ParentPath = Split-Path $DestinationPath -Parent
  $null = New-Item -Path $ParentPath -ItemType Directory -Force
  $PackagePath = Join-Path $ParentPath "$($Lock.RuntimeId).$($Lock.Version).$([guid]::NewGuid().ToString('N')).nupkg"
  $StagingPath = Join-Path $ParentPath ".staging-$([guid]::NewGuid().ToString('N'))"
  $LastError = $null
  try {
    for ($Attempt = 1; $Attempt -le $MaximumRetryCount; $Attempt++) {
      try {
        Invoke-WebRequest -Uri $Lock.PackageUri -OutFile $PackagePath -MaximumRetryCount 0 -ErrorAction Stop
        $LastError = $null
        break
      } catch {
        $LastError = $_
        if ($Attempt -lt $MaximumRetryCount) { Start-Sleep -Seconds ([Math]::Min($Attempt * 3, 10)) }
      }
    }
    if ($LastError) {
      throw "Failed to download $($Lock.RuntimeId) $($Lock.Version): $($LastError.Exception.Message)"
    }

    $ActualHash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash
    if ($ActualHash -cne ([string]$Lock.PackageSha256).ToUpperInvariant()) {
      throw "The $($Lock.RuntimeId) package hash is '${ActualHash}', expected '$($Lock.PackageSha256)'"
    }

    $null = New-Item -Path $StagingPath -ItemType Directory -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Archive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
      foreach ($Entry in $Archive.Entries) {
        $RelativePath = switch -Regex ($Entry.FullName) {
          '^lib/netstandard2\.0/Microsoft\.Playwright\.dll$' { 'Microsoft.Playwright.dll'; break }
          '^\.playwright/(?:package/|node/win32_x64/)' { $Entry.FullName; break }
          '^\.playwright/node/LICENSE$' { $Entry.FullName; break }
          '^(?:LICENSE|NOTICE|ThirdPartyNotices\.txt)$' { Join-Path 'Notices' $Entry.FullName; break }
          default { $null }
        }
        if (-not $RelativePath -or $Entry.FullName.EndsWith('/')) { continue }

        # Resolve each archive entry beneath staging before writing to prevent traversal.
        $OutputPath = [IO.Path]::GetFullPath((Join-Path $StagingPath ($RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)))
        $StagingPrefix = [IO.Path]::GetFullPath($StagingPath).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $OutputPath.StartsWith($StagingPrefix, [StringComparison]::OrdinalIgnoreCase)) {
          throw "The Playwright package contains an unsafe path: $($Entry.FullName)"
        }
        $null = New-Item -Path (Split-Path $OutputPath -Parent) -ItemType Directory -Force
        $InputStream = $Entry.Open()
        $OutputStream = [IO.File]::Create($OutputPath)
        try { $InputStream.CopyTo($OutputStream) } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
      }
    } finally {
      $Archive.Dispose()
    }

    if (-not (Test-DumplingsPlaywrightRuntime -Path $StagingPath -Version $Lock.Version)) {
      throw 'The extracted Playwright runtime is incomplete or has an unexpected assembly version.'
    }
    if (Test-Path -LiteralPath $DestinationPath) { Remove-Item -LiteralPath $DestinationPath -Recurse -Force }
    Move-Item -LiteralPath $StagingPath -Destination $DestinationPath
  } finally {
    Remove-Item -LiteralPath $PackagePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StagingPath -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Initialize-DumplingsPlaywrightRuntime {
  <#
  .SYNOPSIS
    Restore or validate the pinned Playwright runtime and return its directory.
  .PARAMETER LockPath
    Path to PlaywrightRuntime.psd1.
  .PARAMETER CachePath
    Optional parent directory for versioned runtimes.
  .PARAMETER MaximumRetryCount
    Number of package download attempts.
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [string]$LockPath,

    [string]$CachePath,

    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 3
  )

  $Lock = Get-DumplingsPlaywrightRuntimeLock -LockPath $LockPath
  $RuntimePath = Get-DumplingsPlaywrightRuntimePath -CachePath $CachePath -Version $Lock.Version -RuntimeId $Lock.RuntimeId
  if (Test-DumplingsPlaywrightRuntime -Path $RuntimePath -Version $Lock.Version) { return $RuntimePath }

  $MutexName = "Local\Dumplings-PlaywrightRuntime-$($Lock.RuntimeId -replace '[^0-9A-Za-z]', '-')-$($Lock.Version -replace '[^0-9A-Za-z]', '-')"
  $Mutex = [Threading.Mutex]::new($false, $MutexName)
  $Acquired = $false
  try {
    try { $Acquired = $Mutex.WaitOne([timespan]::FromMinutes(10)) } catch [Threading.AbandonedMutexException] { $Acquired = $true }
    if (-not $Acquired) { throw "Timed out waiting for the Playwright runtime cache lock '${MutexName}'" }
    if (-not (Test-DumplingsPlaywrightRuntime -Path $RuntimePath -Version $Lock.Version)) {
      Save-DumplingsPlaywrightRuntime -Lock $Lock -DestinationPath $RuntimePath -MaximumRetryCount $MaximumRetryCount
    }
  } finally {
    if ($Acquired) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
  return $RuntimePath
}

Export-ModuleMember -Function Initialize-DumplingsPlaywrightRuntime, Test-DumplingsPlaywrightRuntime
