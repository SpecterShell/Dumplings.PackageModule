# SPDX-License-Identifier: Apache-2.0

function Close-DumplingsPlaywrightHookPool {
  <#
  .SYNOPSIS
    Dispose the shared Playwright pool during runner shutdown.
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

  $PoolStorageKey = '__DumplingsPlaywrightLeasePool'
  [Threading.Monitor]::Enter($Storage.SyncRoot)
  try {
    if (-not $Storage.ContainsKey($PoolStorageKey)) { return }
    try {
      $Storage[$PoolStorageKey].Dispose()
    } finally {
      if (-not $KeepInStorage) { $Storage.Remove($PoolStorageKey) }
    }
  } finally {
    [Threading.Monitor]::Exit($Storage.SyncRoot)
  }
}
