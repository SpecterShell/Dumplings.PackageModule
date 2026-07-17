# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
  Wake WebDriver waiters before timed-out worker jobs are removed forcibly.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

. (Join-Path $PSScriptRoot 'WebDriver.Common.ps1')
Close-DumplingsWebDriverHookPool -Storage $Context.Storage -KeepInStorage
