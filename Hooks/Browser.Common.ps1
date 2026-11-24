# SPDX-License-Identifier: Apache-2.0

function Close-DumplingsBrowserHookPool {
  <#
  .SYNOPSIS
    Dispose a browser broker without holding the global shared-storage lock.
  .PARAMETER Storage
    Runner-owned synchronized storage.
  .PARAMETER Name
    Browser broker whose lifetime is ending.
  .PARAMETER KeepInStorage
    Retain the closed broker during forced worker shutdown to prevent recreation.
  #>
  param (
    [Parameter(Mandatory)][Collections.IDictionary]$Storage,
    [Parameter(Mandatory)][ValidateSet('WebDriver', 'Playwright')][string]$Name,
    [switch]$KeepInStorage
  )
  if ($Storage -isnot [hashtable] -or -not $Storage.IsSynchronized) { return }
  $Key = "__Dumplings${Name}LeasePool"
  [Threading.Monitor]::Enter($Storage.SyncRoot)
  try { $Pool = $Storage[$Key] } finally { [Threading.Monitor]::Exit($Storage.SyncRoot) }
  if ($null -eq $Pool) { return }
  try { $Pool.Dispose() }
  finally {
    if (-not $KeepInStorage) {
      [Threading.Monitor]::Enter($Storage.SyncRoot)
      try { if ([object]::ReferenceEquals($Storage[$Key], $Pool)) { $Storage.Remove($Key) } }
      finally { [Threading.Monitor]::Exit($Storage.SyncRoot) }
    }
  }
}
