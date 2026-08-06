# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Complete browser leases and surface preemption as task failure, then record
  the task outcome for the runner status report.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

try {
  $OwnerStorageKeys = @('PackageModule.WebDriver.OwnerId', 'PackageModule.Playwright.OwnerId')
  $OwnerId = $Context.Items[$OwnerStorageKeys[0]] ?? $Context.Items[$OwnerStorageKeys[1]]
  if ([string]::IsNullOrWhiteSpace($OwnerId)) {
    Remove-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name DumplingsPlaywrightLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
    return
  }

  $TaskWasSuccessful = $Context.Task.InvocationSucceeded -or $Context.Task.InvocationSkipped
  $TerminalFailures = [Collections.Generic.List[string]]::new()
  try {
    foreach ($LeaseType in 'WebDriver', 'Playwright') {
      $Command = Get-Command -Name "Complete-Dumplings${LeaseType}Lease" -ErrorAction SilentlyContinue
      if (-not $Command) { continue }
      try {
        $Outcome = & $Command -OwnerId $OwnerId -Failed:(-not $TaskWasSuccessful)
      } catch {
        $TerminalFailures.Add("${LeaseType} lease '${OwnerId}' could not be completed: $($_.Exception.Message)")
        continue
      }
      if ($TaskWasSuccessful -and $Outcome -and ([string]$Outcome.Outcome -in @('Failed', 'TimedOut', 'Disposed'))) {
        $TerminalFailures.Add("${LeaseType} lease '${OwnerId}' ended as $($Outcome.Outcome): $($Outcome.Message)")
      }
    }
    if ($TerminalFailures.Count -gt 0) {
      $Context.Task.InvocationSucceeded = $false
      $Context.Task.InvocationSkipped = $false
      throw "Browser automation for task '$($Context.TaskName)' failed: $($TerminalFailures -join '; ')"
    }
  } finally {
    foreach ($OwnerStorageKey in $OwnerStorageKeys) { $Context.Items.Remove($OwnerStorageKey) }
    Remove-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name DumplingsPlaywrightLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  }
} finally {
  # Record the task outcome even when browser lease completion above fails the
  # task. Reporting is best-effort and must never fail the task itself.
  try {
    $StatusReportModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Messaging' 'StatusReport.psm1') -Force -PassThru
    & $StatusReportModule {
      param ($Storage, $TaskName, $Task, $InvocationError)
      Register-DumplingsTaskStatus -Storage $Storage -TaskName $TaskName -Task $Task -InvocationError $InvocationError
    } $Context.Storage $Context.TaskName $Context.Task $Context.InvocationError
  } catch {
    Write-Warning -Message "Failed to record the status of task '$($Context.TaskName)': $($_.Exception.Message)"
  }
}
