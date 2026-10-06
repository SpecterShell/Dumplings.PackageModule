# SPDX-License-Identifier: Apache-2.0
. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  . (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
  $Script:WaitScript = Join-Path $Script:DumplingsRepositoryRoot '.agents\skills\analyze-winget-installer\scripts\Wait-WinGetVMProcess.ps1'
  $Script:PowerShellPath = Join-Path $PSHOME 'pwsh.exe'

  function Start-ControlledWaitTestProcess {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Diagnostics.Process])]
    param ([string]$Command, [string]$HostPath = $Script:PowerShellPath)
    if (-not $PSCmdlet.ShouldProcess($HostPath, 'Start a controlled process for a wait test')) { return }
    $StartInfo = [Diagnostics.ProcessStartInfo]::new($HostPath)
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command)))) {
      $StartInfo.ArgumentList.Add($Argument)
    }
    $Process = [Diagnostics.Process]::Start($StartInfo)
    $Script:OwnedProcesses.Add($Process)
    return $Process
  }
}

Describe 'Bounded VM process waiter' -Tag Unit {
  BeforeEach { $Script:OwnedProcesses = [Collections.Generic.List[Diagnostics.Process]]::new() }
  AfterEach {
    foreach ($Process in $Script:OwnedProcesses) {
      if (-not $Process.HasExited) { $Process.Kill($true); $null = $Process.WaitForExit(10000) }
      $Process.Dispose()
    }
  }

  It 'returns the actual exit code without disposing a borrowed process' {
    $Process = Start-ControlledWaitTestProcess 'exit 23'
    $Result = & $Script:WaitScript -Process $Process -TimeoutSeconds 10
    $Result.Completed | Should -BeTrue
    $Result.TimedOut | Should -BeFalse
    $Result.ExitCode | Should -Be 23
    $Result.WaitScope | Should -BeExactly 'Process'
    $Result.ProcessId | Should -Be $Process.Id
    { $null = $Process.Handle } | Should -Not -Throw
  }

  It 'supports an already-exited process object' {
    $Process = Start-ControlledWaitTestProcess 'exit 37'
    $Process.WaitForExit(10000) | Should -BeTrue
    $Result = & $Script:WaitScript -Process $Process -TimeoutSeconds 1
    $Result.Completed | Should -BeTrue
    $Result.ExitCode | Should -Be 37
  }

  It 'leaves the process running on timeout and never invents a success code' {
    $Process = Start-ControlledWaitTestProcess 'Start-Sleep -Seconds 30'
    $Result = & $Script:WaitScript -Process $Process -TimeoutSeconds 1
    $Result.TimedOut | Should -BeTrue
    $Result.Completed | Should -BeFalse
    $Result.ExitCode | Should -BeNullOrEmpty
    $Process.HasExited | Should -BeFalse
  }

  It 'can attach to a known running PID' {
    $Process = Start-ControlledWaitTestProcess 'Start-Sleep -Seconds 1; exit 45'
    $Result = & $Script:WaitScript -Id $Process.Id -TimeoutSeconds 10
    $Result.Completed | Should -BeTrue
    $Result.ExitCode | Should -Be 45
    $Result.ProcessId | Should -Be $Process.Id
  }

  It 'does not wait for a launched descendant after the outer process exits' {
    $ChildCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 30'))
    $ParentCommand = "`$Child = Start-Process -FilePath '$Script:PowerShellPath' -ArgumentList '-NoProfile -NonInteractive -EncodedCommand $ChildCommand' -WindowStyle Hidden -PassThru; [Console]::WriteLine(`$Child.Id); exit 0"
    $Parent = Start-ControlledWaitTestProcess $ParentCommand
    $Line = $Parent.StandardOutput.ReadLineAsync()
    $Line.Wait(10000) | Should -BeTrue
    $Child = Get-Process -Id ([int]$Line.Result) -ErrorAction Stop
    $Script:OwnedProcesses.Add($Child)
    $Result = & $Script:WaitScript -Process $Parent -TimeoutSeconds 5
    $Result.Completed | Should -BeTrue
    $Result.ExitCode | Should -Be 0
    $Child.HasExited | Should -BeFalse
  }

  It 'rejects invalid IDs and timeout values' {
    { & $Script:WaitScript -Id 0 } | Should -Throw
    { & $Script:WaitScript -Id $PID -TimeoutSeconds 0 } | Should -Throw
    { & $Script:WaitScript -Id 2147483647 } | Should -Throw
  }

  It 'runs in the Windows PowerShell 5.1 guest runtime' {
    $WindowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $Command = "`$Process = Start-Process -FilePath `$env:ComSpec -ArgumentList '/d /c exit 31' -WindowStyle Hidden -PassThru; try { & '$Script:WaitScript' -Process `$Process -TimeoutSeconds 5 | ConvertTo-Json -Compress } finally { `$Process.Dispose() }"
    $Process = Start-ControlledWaitTestProcess -Command $Command -HostPath $WindowsPowerShell
    $Process.WaitForExit(10000) | Should -BeTrue
    $Process.ExitCode | Should -Be 0
    $Result = $Process.StandardOutput.ReadToEnd() | ConvertFrom-Json
    $Result.Completed | Should -BeTrue
    $Result.ExitCode | Should -Be 31
  }
}
