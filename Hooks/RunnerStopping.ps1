# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Dispose and remove process-wide browser-automation pools at runner shutdown.
#>
param (
  [Parameter(Mandatory)]
  [System.Collections.IDictionary]$Context
)

. (Join-Path $PSScriptRoot 'Browser.Common.ps1')
$CleanupFailures = [Collections.Generic.List[string]]::new()
try {
  $QueueModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Messaging' 'MessageQueue.psm1') -PassThru
  & $QueueModule { param($Storage) Stop-MessageQueue -Storage $Storage } $Context.Storage
} catch { $CleanupFailures.Add("Message queue cleanup failed: $_") }
foreach ($Browser in 'WebDriver', 'Playwright') {
  try { Close-DumplingsBrowserHookPool -Storage $Context.Storage -Name $Browser }
  catch { $CleanupFailures.Add("$Browser cleanup failed: $_") }
}
foreach ($Failure in $CleanupFailures) { Write-Warning $Failure }

# Export the task status report after every queue and pool has been drained.
# The report is best-effort and must not mask the cleanup above.
if ($Context.Contains('TaskStates') -and $null -ne $Context.TaskStates) {
  try {
    $StatusReportModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Messaging' 'StatusReport.psm1') -PassThru
    $null = & $StatusReportModule {
      param ($Context)
      Export-DumplingsTaskStatusReport -TaskStates $Context.TaskStates -Storage $Context.Storage -OutputPath $Context.OutputPath -StopReason ([string]$Context.StopReason)
    } $Context
  } catch {
    Write-Warning -Message "Failed to export the task status report: $($_.Exception.Message)"
  }
}
