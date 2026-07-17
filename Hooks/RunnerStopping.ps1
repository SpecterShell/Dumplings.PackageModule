# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
  Dispose and remove the process-wide WebDriver pool at runner shutdown.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

. (Join-Path $PSScriptRoot 'WebDriver.Common.ps1')
Close-DumplingsWebDriverHookPool -Storage $Context.Storage
