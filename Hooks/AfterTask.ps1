# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
  Complete a task's WebDriver lease and surface preemption as task failure.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

$OwnerStorageKey = 'PackageModule.WebDriver.OwnerId'
$OwnerId = $Context.Items[$OwnerStorageKey]
if ([string]::IsNullOrWhiteSpace($OwnerId)) {
  Remove-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  return
}

$TaskWasSuccessful = $Context.Task.InvocationSucceeded -or $Context.Task.InvocationSkipped
try {
  $Outcome = Complete-DumplingsWebDriverLease -OwnerId $OwnerId -Failed:(-not $TaskWasSuccessful)
  if ($TaskWasSuccessful -and $Outcome -and ([string]$Outcome.Outcome -in @('Failed', 'TimedOut', 'Disposed'))) {
    $Context.Task.InvocationSucceeded = $false
    $Context.Task.InvocationSkipped = $false
    throw "WebDriver lease '${OwnerId}' for task '$($Context.TaskName)' ended as $($Outcome.Outcome): $($Outcome.Message)"
  }
} finally {
  $Context.Items.Remove($OwnerStorageKey)
  Remove-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
}
