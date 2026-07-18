$Script:MessageQueueModulePath = Join-Path $PSScriptRoot '..\Libraries\MessageQueue.psm1'
Import-Module $Script:MessageQueueModulePath -Force

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Index.ps1') -Force
}

Describe 'Message queue broker' {
  BeforeEach {
    $Script:Broker = [Dumplings.Messaging.MessageQueueBroker]::new()
  }

  AfterEach {
    $Script:Broker.Dispose()
  }

  It 'takes distinct requests in FIFO order' {
    $First = $Script:Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'first' })
    $Second = $Script:Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'second' })

    $FirstWork = $Script:Broker.Take('target', [Threading.CancellationToken]::None)
    $SecondWork = $Script:Broker.Take('target', [Threading.CancellationToken]::None)

    $FirstWork.Ticket.RequestId | Should -Be $First.RequestId
    $SecondWork.Ticket.RequestId | Should -Be $Second.RequestId
    $Script:Broker.Complete($FirstWork, $true, $null)
    $Script:Broker.Complete($SecondWork, $true, $null)
  }

  It 'supersedes only a pending request with the same queue key' {
    $Old = $Script:Broker.Enqueue('Telegram', 'target', 'Package:Example', 'session', @{ Message = 'old' })
    $New = $Script:Broker.Enqueue('Telegram', 'target', 'package:example', 'session', @{ Message = 'new' })

    $Old.State | Should -Be 'Superseded'
    $Old.SupersededByRequestId | Should -Be $New.RequestId
    $Work = $Script:Broker.Take('target', [Threading.CancellationToken]::None)
    $Work.Ticket.RequestId | Should -Be $New.RequestId
    $Script:Broker.Complete($Work, $true, $null)
  }

  It 'does not interrupt an active request when a newer update arrives' {
    $Old = $Script:Broker.Enqueue('Telegram', 'target', 'package', 'session', @{ Message = 'old' })
    $OldWork = $Script:Broker.Take('target', [Threading.CancellationToken]::None)
    $New = $Script:Broker.Enqueue('Telegram', 'target', 'package', 'session', @{ Message = 'new' })

    $Old.State | Should -Be 'Active'
    $New.State | Should -Be 'Pending'
    $Script:Broker.Complete($OldWork, $true, $null)
    $NewWork = $Script:Broker.Take('target', [Threading.CancellationToken]::None)
    $NewWork.Ticket.RequestId | Should -Be $New.RequestId
    $Script:Broker.Complete($NewWork, $true, $null)
  }

  It 'keeps custom requests without queue keys as separate entries' {
    $First = $Script:Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'one' })
    $Second = $Script:Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'two' })

    $Script:Broker.Take('target', [Threading.CancellationToken]::None).Ticket.RequestId | Should -Be $First.RequestId
    $Script:Broker.Take('target', [Threading.CancellationToken]::None).Ticket.RequestId | Should -Be $Second.RequestId
  }

  It 'allows separate targets to make progress independently' {
    $First = $Script:Broker.Enqueue('Telegram', 'target-a', 'package', 'session', @{ Message = 'one' })
    $Second = $Script:Broker.Enqueue('Matrix', 'target-b', 'package', 'session', @{ Message = 'two' })

    $Script:Broker.Take('target-a', [Threading.CancellationToken]::None).Ticket.RequestId | Should -Be $First.RequestId
    $Script:Broker.Take('target-b', [Threading.CancellationToken]::None).Ticket.RequestId | Should -Be $Second.RequestId
  }

  It 'does not retain a request rejected by a cancelled target' {
    $Ticket = $Script:Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'first' })
    $Script:Broker.CancelTarget('target', 'worker failed')

    { $Script:Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'second' }) } |
      Should -Throw '*no longer accepting*'
    $Script:Broker.GetTickets().Count | Should -Be 1
    $Script:Broker.GetTickets()[0].RequestId | Should -Be $Ticket.RequestId
  }
}

Describe 'Message queue rate limiting' {
  It 'uses the injected clock for the normal message interval and Retry-After' {
    $Clock = [pscustomobject]@{
      UtcNow = [datetime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
      Delays = [Collections.Generic.List[timespan]]::new()
    }
    $UtcNow = [Func[datetime]] { $Clock.UtcNow }.GetNewClosure()
    $Wait = [Action[timespan, Threading.CancellationToken]] {
      param ($Delay, $CancellationToken)
      $CancellationToken.ThrowIfCancellationRequested()
      $Clock.Delays.Add($Delay)
      $Clock.UtcNow = $Clock.UtcNow.Add($Delay)
    }.GetNewClosure()
    $Context = [Dumplings.Messaging.MessageRateLimitContext]::new(
      [timespan]::FromSeconds(1), 30, 60, [Threading.CancellationToken]::None, $UtcNow, $Wait
    )

    $Context.MarkAttemptCompleted()
    $Context.Wait()
    $Context.SetRetryAfter([timespan]::FromSeconds(7))
    $Context.Wait()

    $Clock.Delays.Count | Should -Be 2
    $Clock.Delays[0].TotalSeconds | Should -Be 1
    $Clock.Delays[1].TotalSeconds | Should -Be 7
  }

  It 'exposes the queue retry bounds to transport operations' {
    $Context = [Dumplings.Messaging.MessageRateLimitContext]::new(
      [timespan]::Zero, 12, 34, [Threading.CancellationToken]::None
    )

    $Context.MaximumRetryDelaySeconds | Should -Be 12
    $Context.MaximumTotalRetryDelaySeconds | Should -Be 34
  }
}

Describe 'Message queue PowerShell orchestration' {
  InModuleScope MessageQueue {
    It 'hashes targets without exposing tokens or destination values' {
      $Target = Get-MessageQueueTargetId -Transport Telegram -Component @('secret-token', 'private-chat')

      $Target | Should -Match '^Telegram:[0-9A-F]{64}$'
      $Target | Should -Not -Match 'secret-token|private-chat'
    }

    It 'reuses a queue-owned session across requests with the same session key' {
      $Runtime = New-MessageQueueRuntime
      $Runtime.IntervalSeconds = 0
      $script:SessionIdentities = [Collections.Generic.List[int]]::new()
      Mock Send-TelegramMessage {
        if ($null -eq $Session) { throw 'The queue-owned session was null.' }
        $script:SessionIdentities.Add([Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Session))
        if ($Session.Count -eq 0) { $Session.Add([Tuple]::Create([string]$Message, [long]1)) }
        return $Session
      }

      $First = $Runtime.Broker.Enqueue('Telegram', 'target', 'first', 'shared', @{ Message = 'one'; ChatID = 'chat'; Token = 'token' })
      $Second = $Runtime.Broker.Enqueue('Telegram', 'target', 'second', 'shared', @{ Message = 'two'; ChatID = 'chat'; Token = 'token' })
      $Runtime.Broker.CompleteAdding()

      Invoke-MessageQueueTargetWorker -Runtime $Runtime -TargetId 'target'

      $First.State | Should -Be 'Succeeded' -Because $First.ErrorMessage
      $Second.State | Should -Be 'Succeeded' -Because $Second.ErrorMessage
      $script:SessionIdentities.Count | Should -Be 2
      $script:SessionIdentities[0] | Should -Be $script:SessionIdentities[1]
      $Runtime.Cancellation.Dispose()
      $Runtime.Broker.Dispose()
    }

    It 'redacts tokens from background failure records' {
      $Runtime = New-MessageQueueRuntime
      $Runtime.IntervalSeconds = 0
      Mock Send-TelegramMessage { throw 'request failed for secret-token' }
      $Ticket = $Runtime.Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'one'; ChatID = 'chat'; Token = 'secret-token' })
      $Runtime.Broker.CompleteAdding()

      Invoke-MessageQueueTargetWorker -Runtime $Runtime -TargetId 'target'

      $Ticket.State | Should -Be 'Failed'
      $Ticket.ErrorMessage | Should -Not -Match 'secret-token'
      $Ticket.ErrorMessage | Should -Match '<redacted>'
      $Runtime.Cancellation.Dispose()
      $Runtime.Broker.Dispose()
    }

    It 'can stop accepting before the final drain' {
      $Runtime = New-MessageQueueRuntime
      $Storage = [hashtable]::Synchronized(@{ '__DumplingsMessageQueueRuntime' = $Runtime })

      Stop-MessageQueue -Storage $Storage -StopAcceptingOnly

      $Runtime.Broker.IsAccepting | Should -BeFalse
      $Storage.ContainsKey('__DumplingsMessageQueueRuntime') | Should -BeTrue

      Stop-MessageQueue -Storage $Storage -DrainTimeoutSeconds 1
      $Storage.ContainsKey('__DumplingsMessageQueueRuntime') | Should -BeFalse
    }

    It 'summarizes background failures during shutdown without throwing' {
      $Runtime = New-MessageQueueRuntime
      $Storage = [hashtable]::Synchronized(@{ '__DumplingsMessageQueueRuntime' = $Runtime })
      $Ticket = $Runtime.Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'one' })
      $Work = $Runtime.Broker.Take('target', [Threading.CancellationToken]::None)
      $Runtime.Broker.Complete($Work, $false, 'synthetic failure')

      $Warnings = & { Stop-MessageQueue -Storage $Storage -DrainTimeoutSeconds 1 } 3>&1

      $Ticket.State | Should -Be 'Failed'
      ($Warnings | Out-String) | Should -Match '1 failed or unsent request'
      ($Warnings | Out-String) | Should -Match 'synthetic failure'
      $Storage.ContainsKey('__DumplingsMessageQueueRuntime') | Should -BeFalse
    }

    It 'starts only one worker when runspaces race for the same target' {
      $Runtime = New-MessageQueueRuntime
      $Storage = [hashtable]::Synchronized(@{ '__DumplingsMessageQueueRuntime' = $Runtime })
      $ModulePath = (Get-Module MessageQueue).Path
      $Ticket = $Runtime.Broker.Enqueue('Telegram', 'target', $null, $null, @{ Message = 'one' })
      $Runtime.Broker.CancelTarget('target', 'synthetic cancellation')
      $Jobs = [Collections.Generic.List[object]]::new()

      try {
        foreach ($Index in 1..4) {
          $Jobs.Add((Start-ThreadJob -ArgumentList $Runtime, $ModulePath -ScriptBlock {
                param ($SharedRuntime, $QueueModulePath)
                Import-Module $QueueModulePath -Force
                & (Get-Module MessageQueue) { param ($Value) Start-MessageQueueTargetWorker -Runtime $Value -TargetId 'target' } $SharedRuntime
              }))
        }
        $null = $Jobs | Wait-Job -Timeout 10
        $JobErrors = @($Jobs | Receive-Job -ErrorAction SilentlyContinue 2>&1)

        $Runtime.Workers.Count | Should -Be 1 -Because ($JobErrors | Out-String)
        $Ticket.State | Should -Be 'Cancelled'
      } finally {
        $Jobs | Remove-Job -Force -ErrorAction SilentlyContinue
        Stop-MessageQueue -Storage $Storage -DrainTimeoutSeconds 2 -WarningAction SilentlyContinue
      }
    }
  }
}

Describe 'PackageTask queued messaging' {
  BeforeAll {
    function global:Write-Log { param ($Object, $Level) $null = $Object, $Level }
    function global:Send-QueuedTelegramMessage {
      param ($Message, $QueueKey, $SessionKey, [switch]$AsMarkdown)
      $Global:MessageQueueTestCalls.Add([pscustomobject]@{
          Message       = $Message
          QueueKey      = $QueueKey
          SessionKey    = $SessionKey
          HasQueueKey   = $PSBoundParameters.ContainsKey('QueueKey')
          HasSessionKey = $PSBoundParameters.ContainsKey('SessionKey')
          UsesMarkdown  = $AsMarkdown.IsPresent
        })
    }
    function New-MessageQueueTestTask {
      param ([string]$Name, [System.Collections.IDictionary]$Config)
      $TaskPath = Join-Path $TestDrive $Name
      $null = New-Item -Path $TaskPath -ItemType Directory -Force
      Set-Content -LiteralPath (Join-Path $TaskPath 'Script.ps1') -Value ''
      $Task = [PackageTask]::new([ordered]@{ Name = $Name; Path = $TaskPath; Config = $Config })
      $Task.CurrentState = [ordered]@{ Version = '1.0'; Installer = @(); Locale = @() }
      return $Task
    }
  }

  BeforeEach {
    $Global:DumplingsPreference = [ordered]@{ EnableMessage = $true }
    $Global:MessageQueueTestCalls = [Collections.Generic.List[object]]::new()
  }

  It 'uses effective WinGet identifier precedence for state coalescing' {
    $Task = New-MessageQueueTestTask -Name Example -Config ([ordered]@{
        WinGetIdentifier           = 'Example.Reference'
        WinGetPackageIdentifier    = 'Example.PackageReference'
        WinGetNewIdentifier        = 'Example.LegacyTarget'
        WinGetNewPackageIdentifier = 'Example.Target'
      })

    $Task.Message()

    $Global:MessageQueueTestCalls[0].QueueKey | Should -BeExactly 'PackageState:Example.Target:0'
    $Global:MessageQueueTestCalls[0].SessionKey | Should -BeExactly 'PackageState:Example.Target:0'
  }

  It 'falls back to task name and advances the session generation on reset' {
    $Task = New-MessageQueueTestTask -Name FallbackTask -Config ([ordered]@{})

    $Task.Message()
    $Task.ResetMessage()
    $Task.Message()

    $Global:MessageQueueTestCalls.QueueKey | Should -Be @('PackageState:FallbackTask:0', 'PackageState:FallbackTask:1')
  }

  It 'queues custom messages without a coalescing or session key' {
    $Task = New-MessageQueueTestTask -Name Example -Config ([ordered]@{ WinGetIdentifier = 'Example.Package' })

    $Task.Message('custom notification')

    $Global:MessageQueueTestCalls[0].HasQueueKey | Should -BeFalse
    $Global:MessageQueueTestCalls[0].HasSessionKey | Should -BeFalse
  }

  AfterAll {
    Remove-Item -Path 'Function:\Write-Log' -Force -ErrorAction Ignore
    Remove-Item -Path 'Function:\Send-QueuedTelegramMessage' -Force -ErrorAction Ignore
    Remove-Item -Path 'Function:\New-MessageQueueTestTask' -Force -ErrorAction Ignore
    Remove-Variable -Name MessageQueueTestCalls -Scope Global -ErrorAction Ignore
  }
}
