# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Wake browser-automation waiters before timed-out workers are removed forcibly.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

$QueueModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'MessageQueue.psm1') -Force -PassThru
& $QueueModule {
  param ($Storage)
  Stop-MessageQueue -Storage $Storage -StopAcceptingOnly
} $Context.Storage

. (Join-Path $PSScriptRoot 'WebDriver.Common.ps1')
Close-DumplingsWebDriverHookPool -Storage $Context.Storage -KeepInStorage
. (Join-Path $PSScriptRoot 'Playwright.Common.ps1')
Close-DumplingsPlaywrightHookPool -Storage $Context.Storage -KeepInStorage
