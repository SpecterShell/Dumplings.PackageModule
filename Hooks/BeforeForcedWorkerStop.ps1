# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
  Wake WebDriver waiters before timed-out worker jobs are removed forcibly.
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
