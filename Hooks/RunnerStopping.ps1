# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Dispose and remove process-wide browser-automation pools at runner shutdown.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

$QueueModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Messaging' 'MessageQueue.psm1') -Force -PassThru
& $QueueModule {
  param ($Storage)
  Stop-MessageQueue -Storage $Storage
} $Context.Storage

. (Join-Path $PSScriptRoot 'WebDriver.Common.ps1')
Close-DumplingsWebDriverHookPool -Storage $Context.Storage
. (Join-Path $PSScriptRoot 'Playwright.Common.ps1')
Close-DumplingsPlaywrightHookPool -Storage $Context.Storage

# Export the task status report after every queue and pool has been drained.
# The report is best-effort and must not mask the cleanup above.
if ($Context.Contains('TaskStates') -and $null -ne $Context.TaskStates) {
  try {
    $StatusReportModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Messaging' 'StatusReport.psm1') -Force -PassThru
    $null = & $StatusReportModule {
      param ($Context)
      Export-DumplingsTaskStatusReport -TaskStates $Context.TaskStates -Storage $Context.Storage -OutputPath $Context.OutputPath -StopReason ([string]$Context.StopReason)
    } $Context
  } catch {
    Write-Warning -Message "Failed to export the task status report: $($_.Exception.Message)"
  }
}
