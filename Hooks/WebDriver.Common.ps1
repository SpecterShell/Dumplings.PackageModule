# SPDX-License-Identifier: Apache-2.0

function Close-DumplingsWebDriverHookPool {
  <#
  .SYNOPSIS
    Dispose the shared WebDriver pool during runner shutdown.
  .PARAMETER Storage
    The synchronized runner storage containing the process-wide pool.
  .PARAMETER KeepInStorage
    Retain the disposed pool so workers cannot recreate it before forced stop.
  #>
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Storage,

    [switch]$KeepInStorage
  )

  if ($Storage -isnot [hashtable] -or -not $Storage.IsSynchronized) { return }

  $PoolStorageKey = '__DumplingsWebDriverLeasePool'
  [System.Threading.Monitor]::Enter($Storage.SyncRoot)
  try {
    if (-not $Storage.ContainsKey($PoolStorageKey)) { return }

    try {
      $Storage[$PoolStorageKey].Dispose()
    } finally {
      if (-not $KeepInStorage) { $Storage.Remove($PoolStorageKey) }
    }
  } finally {
    [System.Threading.Monitor]::Exit($Storage.SyncRoot)
  }
}
