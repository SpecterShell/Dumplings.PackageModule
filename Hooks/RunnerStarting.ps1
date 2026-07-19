# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Initialize the shared message queue before Dumplings workers start.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

$QueueModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'MessageQueue.psm1') -Force -PassThru
& $QueueModule {
  param ($Storage)
  Initialize-MessageQueue -Storage $Storage
} $Context.Storage
