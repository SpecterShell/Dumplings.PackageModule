# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Assign one browser-automation lease owner before a Dumplings task runs.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

$OwnerId = "$($Context.WorkerName)/$($Context.TaskName)/$($Context.InvocationId)"
$Context.Items['PackageModule.WebDriver.OwnerId'] = $OwnerId
$Context.Items['PackageModule.Playwright.OwnerId'] = $OwnerId
$Global:DumplingsWebDriverLeaseOwnerId = $OwnerId
$Global:DumplingsPlaywrightLeaseOwnerId = $OwnerId
