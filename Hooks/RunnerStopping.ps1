# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Dispose and remove the process-wide WebDriver pool at runner shutdown.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

$QueueModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'MessageQueue.psm1') -Force -PassThru
& $QueueModule {
  param ($Storage)
  Stop-MessageQueue -Storage $Storage
} $Context.Storage

. (Join-Path $PSScriptRoot 'WebDriver.Common.ps1')
Close-DumplingsWebDriverHookPool -Storage $Context.Storage
