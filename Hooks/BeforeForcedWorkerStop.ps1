# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Wake browser-automation waiters before timed-out workers are removed forcibly.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

. (Join-Path $PSScriptRoot 'Browser.Common.ps1')
$CleanupFailures = [Collections.Generic.List[string]]::new()
try {
  $QueueModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Messaging' 'MessageQueue.psm1') -PassThru
  & $QueueModule { param($Storage) Stop-MessageQueue -Storage $Storage -StopAcceptingOnly } $Context.Storage
} catch { $CleanupFailures.Add("Message queue cleanup failed: $_") }
foreach ($Browser in 'WebDriver', 'Playwright') {
  try { Close-DumplingsBrowserHookPool -Storage $Context.Storage -Name $Browser -KeepInStorage }
  catch { $CleanupFailures.Add("$Browser cleanup failed: $_") }
}
foreach ($Failure in $CleanupFailures) { Write-Warning $Failure }
