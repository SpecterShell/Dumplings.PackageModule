# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Assign a unique WebDriver lease owner before a Dumplings task runs.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

$OwnerId = "$($Context.WorkerName)/$($Context.TaskName)/$($Context.InvocationId)"
$Context.Items['PackageModule.WebDriver.OwnerId'] = $OwnerId
$Global:DumplingsWebDriverLeaseOwnerId = $OwnerId
