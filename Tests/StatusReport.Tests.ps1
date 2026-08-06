$Script:StatusReportModulePath = Join-Path $PSScriptRoot '..\Libraries\Messaging\StatusReport.psm1'
Import-Module $Script:StatusReportModulePath -Force

Describe 'Task status registration' {
  BeforeEach {
    $Script:Storage = [hashtable]::Synchronized(@{})
  }

  It 'records package details from a task object' {
    $Task = [pscustomobject]@{
      Config       = [ordered]@{ WinGetIdentifier = 'Acme.Widget' }
      CurrentState = [ordered]@{ Version = '1.2.3'; Installer = @(); Locale = @() }
      LastState    = [ordered]@{ Version = '1.2.2'; Installer = @(); Locale = @() }
      Status       = [System.Collections.Generic.List[string]]@('New', 'Updated')
      Logs         = [System.Collections.Generic.List[string]]@('New task', 'Checked 1.2.3')
    }

    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Widget' -Task $Task

    $Record = $Script:Storage['__DumplingsTaskStatusRecords']['Acme.Widget']
    $Record.Identifier | Should -Be 'Acme.Widget'
    $Record.Version | Should -Be '1.2.3'
    $Record.Statuses | Should -Be @('New', 'Updated')
    $Record.Logs | Should -Be @('New task', 'Checked 1.2.3')
    $Record.Error | Should -BeNullOrEmpty
  }

  It 'prefers the effective submission identifier over the current identifier' {
    $Task = [pscustomobject]@{
      Config = [ordered]@{ WinGetIdentifier = 'Acme.Widget'; WinGetNewPackageIdentifier = 'Acme.WidgetPro' }
    }

    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Widget' -Task $Task

    $Script:Storage['__DumplingsTaskStatusRecords']['Acme.Widget'].Identifier | Should -Be 'Acme.WidgetPro'
  }

  It 'falls back to the last state version when the current state has none' {
    $Task = [pscustomobject]@{
      Config       = [ordered]@{}
      CurrentState = [ordered]@{ Version = $null }
      LastState    = [ordered]@{ Version = '1.2.2' }
    }

    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Widget' -Task $Task

    $Script:Storage['__DumplingsTaskStatusRecords']['Acme.Widget'].Version | Should -Be '1.2.2'
  }

  It 'tolerates task objects without package state properties' {
    $Task = [pscustomobject]@{ Config = [ordered]@{ Type = 'SimpleTask' } }

    { Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Plain' -Task $Task } | Should -Not -Throw

    $Record = $Script:Storage['__DumplingsTaskStatusRecords']['Acme.Plain']
    $Record.Identifier | Should -BeNullOrEmpty
    $Record.Version | Should -BeNullOrEmpty
    $Record.Statuses | Should -BeNullOrEmpty
    $Record.Logs | Should -BeNullOrEmpty
  }

  It 'keeps only the most recent logs and truncates long entries' {
    $LongEntry = 'x' * 600
    $Task = [pscustomobject]@{
      Config = [ordered]@{}
      Logs   = [System.Collections.Generic.List[string]]@(@('oldest') + @(1..25 | ForEach-Object { "entry ${_}" }) + @($LongEntry))
    }

    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Widget' -Task $Task

    $Record = $Script:Storage['__DumplingsTaskStatusRecords']['Acme.Widget']
    $Record.Logs.Count | Should -Be 20
    $Record.Logs | Should -Not -Contain 'oldest'
    $Record.Logs[-1].EndsWith('...[truncated]') | Should -BeTrue
    $Record.Logs[-1].Length | Should -BeLessThan 600
  }

  It 'records the invocation error' {
    $ErrorRecord = $null
    try { throw 'simulated failure' } catch { $ErrorRecord = $_ }

    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Broken' -Task $null -InvocationError $ErrorRecord

    $Script:Storage['__DumplingsTaskStatusRecords']['Acme.Broken'].Error | Should -BeLike '*simulated failure*'
  }
}

Describe 'Task status report export' {
  BeforeEach {
    $Script:Storage = [hashtable]::Synchronized(@{})
    $Script:TaskStates = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Script:OutputPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  }

  It 'merges task states with recorded details and writes both report files' {
    $Script:TaskStates['Acme.Widget'] = 'Succeeded'
    $Script:TaskStates['Acme.Broken'] = 'Failed'
    $Script:TaskStates['Acme.Dependent'] = 'Blocked'
    $Task = [pscustomobject]@{
      Config       = [ordered]@{ WinGetIdentifier = 'Acme.Widget' }
      CurrentState = [ordered]@{ Version = '1.2.3' }
      Status       = [System.Collections.Generic.List[string]]@('Updated')
      Logs         = [System.Collections.Generic.List[string]]@('Checked 1.2.3')
    }
    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Widget' -Task $Task
    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Broken' -Task $null -InvocationError 'boom'

    $ReportPath = Export-DumplingsTaskStatusReport -TaskStates $Script:TaskStates -Storage $Script:Storage -OutputPath $Script:OutputPath -StopReason 'Completed'

    $Json = Get-Content -LiteralPath (Join-Path $ReportPath 'status.json') -Raw | ConvertFrom-Json
    $Json.stopReason | Should -Be 'Completed'
    $Json.summary.total | Should -Be 3
    $Json.summary.succeeded | Should -Be 1
    $Json.summary.failed | Should -Be 1
    $Json.summary.blocked | Should -Be 1
    @($Json.tasks).Count | Should -Be 3
    # Failures are surfaced first
    $Json.tasks[0].name | Should -Be 'Acme.Broken'
    $Json.tasks[0].error | Should -Be 'boom'
    $Widget = @($Json.tasks | Where-Object -Property name -EQ -Value 'Acme.Widget')
    $Widget.state | Should -Be 'Succeeded'
    $Widget.identifier | Should -Be 'Acme.Widget'
    $Widget.version | Should -Be '1.2.3'
    @($Widget.statuses) | Should -Be @('Updated')
    @($Widget.logs) | Should -Be @('Checked 1.2.3')
    # Tasks without a recorded detail still appear with their authoritative state
    $Dependent = @($Json.tasks | Where-Object -Property name -EQ -Value 'Acme.Dependent')
    $Dependent.state | Should -Be 'Blocked'
    $Dependent.version | Should -BeNullOrEmpty

    $Html = Get-Content -LiteralPath (Join-Path $ReportPath 'index.html') -Raw
    $Html | Should -BeLike "*fetch('status.json')*"
    $Html | Should -BeLike '*id="expand-all"*'
    $Html | Should -BeLike '*id="collapse-all"*'
    # Expanding 100 or more log sections asks for confirmation first
    $Html | Should -BeLike '*details.length >= 100*'
    # Task data lives only in status.json and is rendered in the browser
    $Html | Should -Not -BeLike '*Acme.Widget*'
  }

  It 'keeps a single task as a JSON array and does not embed task data in the page' {
    $Script:TaskStates['Acme.Broken'] = 'Failed'
    $Task = [pscustomobject]@{
      Config = [ordered]@{}
      Logs   = [System.Collections.Generic.List[string]]@('<script>alert(1)</script>')
    }
    Register-DumplingsTaskStatus -Storage $Script:Storage -TaskName 'Acme.Broken' -Task $Task

    $ReportPath = Export-DumplingsTaskStatusReport -TaskStates $Script:TaskStates -Storage $Script:Storage -OutputPath $Script:OutputPath

    $Json = Get-Content -LiteralPath (Join-Path $ReportPath 'status.json') -Raw | ConvertFrom-Json
    @($Json.tasks).Count | Should -Be 1
    $Json.stopReason | Should -Be 'Completed'
    # Report content is preserved verbatim in the JSON; the page renders it via textContent
    $Json.tasks[0].logs[0] | Should -Be '<script>alert(1)</script>'

    $Html = Get-Content -LiteralPath (Join-Path $ReportPath 'index.html') -Raw
    $Html | Should -Not -BeLike '*alert(1)*'
  }

  It 'writes an empty report when no task was planned' {
    $ReportPath = Export-DumplingsTaskStatusReport -TaskStates $Script:TaskStates -Storage $Script:Storage -OutputPath $Script:OutputPath

    $Json = Get-Content -LiteralPath (Join-Path $ReportPath 'status.json') -Raw | ConvertFrom-Json
    $Json.summary.total | Should -Be 0
    @($Json.tasks).Count | Should -Be 0
    Test-Path -LiteralPath (Join-Path $ReportPath 'index.html') -PathType Leaf | Should -BeTrue
  }
}
