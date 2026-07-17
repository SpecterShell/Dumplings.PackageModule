# SPDX-License-Identifier: MIT

BeforeAll {
  if (-not ([System.Management.Automation.PSTypeName]'Dumplings.WebDriver.WebDriverLeasePool').Type) {
    Add-Type -Path (Join-Path $PSScriptRoot '..' 'Assets' 'WebDriverLeasePool.cs')
  }

  function New-TestWebDriverResource {
    param (
      [Parameter(Mandatory)][string]$Configuration,
      [Collections.Concurrent.ConcurrentQueue[string]]$DisposedResources
    )

    if ($DisposedResources) {
      $Disposable = [Dumplings.WebDriver.Tests.TrackingDisposable]::new($Configuration, $DisposedResources)
      return [Dumplings.WebDriver.WebDriverResource]::new($Disposable, $null, 0, $Configuration, [string[]]@())
    }
    $Stream = [IO.MemoryStream]::new()
    return [Dumplings.WebDriver.WebDriverResource]::new($Stream, $null, 0, $Configuration, [string[]]@())
  }

  if (-not ([System.Management.Automation.PSTypeName]'Dumplings.WebDriver.Tests.TrackingDisposable').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;

namespace Dumplings.WebDriver.Tests
{
    public sealed class TrackingDisposable : IDisposable
    {
        private readonly string _name;
        private readonly ConcurrentQueue<string> _disposed;
        public TrackingDisposable(string name, ConcurrentQueue<string> disposed) { _name = name; _disposed = disposed; }
        public void Dispose() { _disposed.Enqueue(_name); }
    }
}
'@
  }
}

Describe 'WebDriver lease broker' {
  It 'reuses one healthy resource after normal release' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    $FactoryCalls = 0
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] {
        $script:FactoryCalls++
        New-TestWebDriverResource -Configuration 'Edge:Headless'
      }
      $First = $Pool.Acquire('owner-1', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))
      $Pool.Release('owner-1', $First.Generation, 'Released', $false, 'released') | Should -BeTrue
      $Second = $Pool.Acquire('owner-2', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))

      [Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Second.Driver) | Should -Be ([Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($First.Driver))
      $script:FactoryCalls | Should -Be 1
      $Pool.Release('owner-2', $Second.Generation, 'Released', $false, 'released') | Should -BeTrue
    } finally {
      $Pool.Dispose()
    }
  }

  It 'returns the same lease to one owner without extending its quantum' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Headless' }
      $First = $Pool.Acquire('owner', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))
      Start-Sleep -Milliseconds 20
      $Second = $Pool.Acquire('owner', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))

      $Second.Generation | Should -Be $First.Generation
      $Second.ExpiresAtUtc | Should -Be $First.ExpiresAtUtc
      $Pool.Release('owner', $First.Generation, 'Released', $false, 'released') | Should -BeTrue
    } finally {
      $Pool.Dispose()
    }
  }

  It 'starts the quantum only after resource initialization completes' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] {
        Start-Sleep -Milliseconds 200
        New-TestWebDriverResource -Configuration 'Edge:Headless'
      }
      $Lease = $Pool.Acquire('owner', 'Edge:Headless', $Factory, [timespan]::FromMilliseconds(300), [timespan]::FromSeconds(5))

      ($Lease.ExpiresAtUtc - [DateTime]::UtcNow).TotalMilliseconds | Should -BeGreaterThan 200
      $Pool.Release('owner', $Lease.Generation, 'Released', $false, 'released') | Should -BeTrue
    } finally {
      $Pool.Dispose()
    }
  }

  It 'serves queued owners in FIFO order' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    $Order = [Collections.Concurrent.ConcurrentQueue[string]]::new()
    $Jobs = [Collections.Generic.List[object]]::new()
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Headless' }
      $Initial = $Pool.Acquire('initial', 'Edge:Headless', $Factory, [timespan]::FromSeconds(10), [timespan]::FromSeconds(5))

      foreach ($Owner in 'first', 'second', 'third') {
        $Jobs.Add((Start-ThreadJob -ArgumentList $Pool, $Order, $Owner -ScriptBlock {
              param($SharedPool, $SharedOrder, $CurrentOwner)
              $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { throw 'The retained resource should be reused.' }
              $Lease = $SharedPool.Acquire($CurrentOwner, 'Edge:Headless', $Factory, [timespan]::FromSeconds(10), [timespan]::FromSeconds(10))
              $SharedOrder.Enqueue($CurrentOwner)
              $null = $SharedPool.Release($CurrentOwner, $Lease.Generation, 'Released', $false, 'released')
            }))
        $Deadline = [DateTime]::UtcNow.AddSeconds(5)
        while ($Pool.PendingCount -lt $Jobs.Count -and [DateTime]::UtcNow -lt $Deadline) { Start-Sleep -Milliseconds 10 }
      }

      $Pool.Release('initial', $Initial.Generation, 'Released', $false, 'released') | Should -BeTrue
      $Jobs | Wait-Job -Timeout 15 | Should -HaveCount 3
      $Jobs | Receive-Job -ErrorAction Stop
      $Order.ToArray() | Should -Be @('first', 'second', 'third')
    } finally {
      $Jobs | Remove-Job -Force -ErrorAction SilentlyContinue
      $Pool.Dispose()
    }
  }

  It 'renews without waiters and preempts when another owner is queued' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    $Disposed = [Collections.Concurrent.ConcurrentQueue[string]]::new()
    $Waiter = $null
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Headless' -DisposedResources $Disposed }
      $Lease = $Pool.Acquire('owner-1', 'Edge:Headless', $Factory, [timespan]::FromMilliseconds(250), [timespan]::FromSeconds(5))
      Start-Sleep -Milliseconds 350
      $Pool.ActiveOwnerId | Should -BeExactly 'owner-1'

      $Waiter = Start-ThreadJob -ArgumentList $Pool -ScriptBlock {
        param($SharedPool)
        $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] {
          $Stream = [IO.MemoryStream]::new()
          [Dumplings.WebDriver.WebDriverResource]::new($Stream, $null, 0, 'Edge:Headless', [string[]]@())
        }
        $Next = $SharedPool.Acquire('owner-2', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))
        $null = $SharedPool.Release('owner-2', $Next.Generation, 'Released', $false, 'released')
        $Next.OwnerId
      }
      $Waiter | Wait-Job -Timeout 5 | Receive-Job -ErrorAction Stop | Should -BeExactly 'owner-2'

      $Pool.GetOutcome('owner-1').Outcome | Should -Be 'TimedOut'
      $Disposed.ToArray() | Should -Contain 'Edge:Headless'
      $Pool.Release('owner-1', $Lease.Generation, 'Released', $false, 'stale release') | Should -BeFalse
    } finally {
      $Waiter | Remove-Job -Force -ErrorAction SilentlyContinue
      $Pool.Dispose()
    }
  }

  It 'recycles the resource before changing browser configuration' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    $Disposed = [Collections.Concurrent.ConcurrentQueue[string]]::new()
    try {
      $HeadlessFactory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Headless' -DisposedResources $Disposed }
      $VisibleFactory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Visible' -DisposedResources $Disposed }
      $Headless = $Pool.Acquire('headless', 'Edge:Headless', $HeadlessFactory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))
      $null = $Pool.Release('headless', $Headless.Generation, 'Released', $false, 'released')
      $Visible = $Pool.Acquire('visible', 'Edge:Visible', $VisibleFactory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))

      $Disposed.ToArray() | Should -Contain 'Edge:Headless'
      $Pool.ResourceConfiguration | Should -BeExactly 'Edge:Visible'
      $null = $Pool.Release('visible', $Visible.Generation, 'Released', $false, 'released')
    } finally {
      $Pool.Dispose()
    }
  }

  It 'recycles a failed lease and records task outcome events' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    $Disposed = [Collections.Concurrent.ConcurrentQueue[string]]::new()
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Headless' -DisposedResources $Disposed }
      $Lease = $Pool.Acquire('failed-owner', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))
      $Pool.Release('failed-owner', $Lease.Generation, 'Failed', $true, 'test failure') | Should -BeTrue

      $Pool.GetOutcome('failed-owner').Outcome | Should -Be 'Failed'
      $Disposed.ToArray() | Should -Contain 'Edge:Headless'
      $Events = $Pool.DrainEvents()
      $Events.EventType | Should -Contain 'Acquired'
      $Events.EventType | Should -Contain 'Failed'
    } finally {
      $Pool.Dispose()
    }
  }

  It 'wakes queued owners when the pool is disposed' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    $Waiter = $null
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Headless' }
      $null = $Pool.Acquire('owner-1', 'Edge:Headless', $Factory, [timespan]::FromSeconds(10), [timespan]::FromSeconds(5))
      $Waiter = Start-ThreadJob -ArgumentList $Pool -ScriptBlock {
        param($SharedPool)
        try {
          $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { throw 'not reached' }
          $null = $SharedPool.Acquire('owner-2', 'Edge:Headless', $Factory, [timespan]::FromSeconds(10), [timespan]::FromSeconds(10))
          'unexpected'
        } catch {
          ($_.Exception.InnerException ?? $_.Exception).GetType().FullName
        }
      }
      $Deadline = [DateTime]::UtcNow.AddSeconds(5)
      while ($Pool.PendingCount -ne 1 -and [DateTime]::UtcNow -lt $Deadline) { Start-Sleep -Milliseconds 10 }

      $Pool.Dispose()
      $Waiter | Wait-Job -Timeout 5 | Receive-Job | Should -BeLike '*ObjectDisposedException*'
      $Pool.GetOutcome('owner-2').Outcome | Should -Be 'Disposed'
    } finally {
      $Waiter | Remove-Job -Force -ErrorAction SilentlyContinue
      $Pool.Dispose()
    }
  }

  It 'records bounded queue waits as task timeouts' {
    $Pool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
    try {
      $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { New-TestWebDriverResource -Configuration 'Edge:Headless' }
      $Lease = $Pool.Acquire('owner-1', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromSeconds(5))

      { $Pool.Acquire('owner-2', 'Edge:Headless', $Factory, [timespan]::FromSeconds(5), [timespan]::FromMilliseconds(50)) } |
        Should -Throw '*Timed out while waiting*'
      $Pool.GetOutcome('owner-2').Outcome | Should -Be 'TimedOut'
      $null = $Pool.Release('owner-1', $Lease.Generation, 'Released', $false, 'released')
    } finally {
      $Pool.Dispose()
    }
  }
}

Describe 'WebDriver task integration contracts' {
  It 'keeps WebDriver lifecycle integration in PackageModule hooks' {
    $Runner = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' '..' '..' 'Core' 'Index.ps1') -Raw
    $HookRoot = Join-Path $PSScriptRoot '..' 'Hooks'

    $Runner | Should -Not -Match 'WebDriver|__DumplingsWebDriverLeasePool'
    @('BeforeTask.ps1', 'AfterTask.ps1', 'BeforeForcedWorkerStop.ps1', 'RunnerStopping.ps1') |
      ForEach-Object { Test-Path -LiteralPath (Join-Path $HookRoot $_) | Should -BeTrue }
  }

  It 'does not allow task scripts to bypass scoped WebDriver leasing' {
    $TaskRoot = Join-Path $PSScriptRoot '..' '..' '..' 'Tasks'
    $Violations = Get-ChildItem -LiteralPath $TaskRoot -Filter 'Script*.ps1' -File -Recurse |
      Select-String -Pattern '\b(?:Get|New)-(?:Edge|Firefox)Driver\b|\$(?:Edge|Firefox)Driver\.Dispose\(\)'
    $Violations | Should -BeNullOrEmpty
  }
}

Describe 'WebDriver lifecycle hooks' {
  BeforeAll {
    $Script:HookWebDriverModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'WebDriver.psm1') -Force -DisableNameChecking -PassThru
    $Script:HookRoot = Join-Path $PSScriptRoot '..' 'Hooks'
  }

  AfterAll {
    Remove-Module -ModuleInfo $Script:HookWebDriverModule -Force -ErrorAction SilentlyContinue
  }

  BeforeEach {
    $Global:DumplingsStorage = [hashtable]::Synchronized(@{})
    $Global:DumplingsPreference = [ordered]@{ WebDriverLeaseDurationSeconds = 30; Timeout = 60 }
    $Global:DumplingsCache = Join-Path $TestDrive 'WebDriverHookCache'
    $Script:HookTask = [pscustomobject]@{ InvocationSucceeded = $true; InvocationSkipped = $false }
    $Script:HookContext = [ordered]@{
      Storage      = $Global:DumplingsStorage
      WorkerName   = 'DumplingsWok0'
      TaskName     = 'Test.Package'
      InvocationId = 'invocation-id'
      Task         = $Script:HookTask
      Items        = [ordered]@{}
    }
  }

  AfterEach {
    if ($Global:DumplingsStorage.ContainsKey('__DumplingsWebDriverLeasePool')) {
      $Global:DumplingsStorage['__DumplingsWebDriverLeasePool'].Dispose()
      $Global:DumplingsStorage.Remove('__DumplingsWebDriverLeasePool')
    }
    Remove-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  }

  It 'does not create a browser pool when a task never acquires a driver' {
    & (Join-Path $Script:HookRoot 'BeforeTask.ps1') -Context $Script:HookContext
    & (Join-Path $Script:HookRoot 'AfterTask.ps1') -Context $Script:HookContext

    $Global:DumplingsStorage.ContainsKey('__DumplingsWebDriverLeasePool') | Should -BeFalse
    Get-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
  }

  It 'creates the shared pool on first lease acquisition' {
    Mock New-PooledEdgeDriverResource {
      New-TestWebDriverResource -Configuration $Configuration
    } -ModuleName WebDriver
    & (Join-Path $Script:HookRoot 'BeforeTask.ps1') -Context $Script:HookContext

    $Lease = & $Script:HookWebDriverModule { Get-WebDriverLease -Browser Edge -Headless }

    $Lease.OwnerId | Should -BeExactly 'DumplingsWok0/Test.Package/invocation-id'
    $Global:DumplingsStorage.ContainsKey('__DumplingsWebDriverLeasePool') | Should -BeTrue
    $null = Complete-DumplingsWebDriverLease -OwnerId $Lease.OwnerId -Failed
  }

  It 'marks a successful task failed when its lease was preempted' {
    Mock Complete-DumplingsWebDriverLease {
      [pscustomobject]@{ Outcome = 'TimedOut'; Message = 'lease expired under contention' }
    }
    & (Join-Path $Script:HookRoot 'BeforeTask.ps1') -Context $Script:HookContext

    { & (Join-Path $Script:HookRoot 'AfterTask.ps1') -Context $Script:HookContext } | Should -Throw '*Test.Package*TimedOut*'

    $Script:HookTask.InvocationSucceeded | Should -BeFalse
    $Script:HookTask.InvocationSkipped | Should -BeFalse
    Get-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
  }

  It 'retains a disposed pool before forced worker removal and removes it at final shutdown' {
    $Pool = [IO.MemoryStream]::new()
    $Global:DumplingsStorage['__DumplingsWebDriverLeasePool'] = $Pool

    & (Join-Path $Script:HookRoot 'BeforeForcedWorkerStop.ps1') -Context $Script:HookContext

    $Global:DumplingsStorage.ContainsKey('__DumplingsWebDriverLeasePool') | Should -BeTrue
    $Pool.CanRead | Should -BeFalse

    & (Join-Path $Script:HookRoot 'RunnerStopping.ps1') -Context $Script:HookContext
    $Global:DumplingsStorage.ContainsKey('__DumplingsWebDriverLeasePool') | Should -BeFalse
  }
}

Describe 'Scoped WebDriver PowerShell API' {
  BeforeAll {
    $Script:WebDriverModule = Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'WebDriver.psm1') -Force -DisableNameChecking -PassThru
  }

  AfterAll {
    Remove-Module -ModuleInfo $Script:WebDriverModule -Force -ErrorAction SilentlyContinue
  }

  It 'returns script output unchanged and releases a successful lease' {
    Mock Get-EdgeDriver { 'fake-driver' } -ModuleName WebDriver
    Mock Exit-WebDriverLease {} -ModuleName WebDriver

    $Result = @(Use-EdgeDriver -Headless { param($Driver) "${Driver}:one"; 'two' })

    $Result | Should -Be @('fake-driver:one', 'two')
    Should -Invoke Exit-WebDriverLease -ModuleName WebDriver -Times 1 -ParameterFilter { -not $Failed }
  }

  It 'releases a failed lease from finally' {
    Mock Get-EdgeDriver { 'fake-driver' } -ModuleName WebDriver
    Mock Exit-WebDriverLease {} -ModuleName WebDriver

    { Use-EdgeDriver { throw 'test failure' } } | Should -Throw '*test failure*'
    Should -Invoke Exit-WebDriverLease -ModuleName WebDriver -Times 1 -ParameterFilter { $Failed }
  }
}

Describe 'Shared WebDriver real runspace smoke' -Tag Integration {
  It 'uses one real Selenium session and service across thread-job runspaces' -Skip:($env:DUMPLINGS_WEBDRIVER_INTEGRATION -ne '1') {
    $ModulePath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'Libraries' 'WebDriver.psm1')).Path
    $Storage = [hashtable]::Synchronized(@{})
    $CachePath = Join-Path $TestDrive 'WebDriverCache'
    $null = New-Item -Path $CachePath -ItemType Directory -Force
    $Jobs = foreach ($Index in 1..3) {
      Start-ThreadJob -ArgumentList $ModulePath, $Storage, $CachePath, $Index -ScriptBlock {
        param($Module, $SharedStorage, $SharedCache, $Number)

        $Global:DumplingsStorage = $SharedStorage
        $Global:DumplingsPreference = [ordered]@{ WebDriverLeaseDurationSeconds = 30; Timeout = 60 }
        $Global:DumplingsWebDriverLeaseOwnerId = "integration-${Number}"
        $Global:DumplingsCache = $SharedCache
        Import-Module $Module -Force -DisableNameChecking
        Use-EdgeDriver -Headless {
          param($Driver)

          $Driver.Navigate().GoToUrl("data:text/html,<main id='ready'>${Number}</main>")
          [pscustomobject]@{
            SessionId = [string]$Driver.SessionId
            Text      = [OpenQA.Selenium.Support.UI.WebDriverWait]::new($Driver, [timespan]::FromSeconds(10)).Until(
              [System.Func[OpenQA.Selenium.IWebDriver, string]] {
                param([OpenQA.Selenium.IWebDriver]$WebDriver)
                try { $WebDriver.FindElement([OpenQA.Selenium.By]::Id('ready')).Text } catch {}
              }
            )
          }
        }
        Complete-DumplingsWebDriverLease -OwnerId "integration-${Number}" | Out-Null
      }
    }

    try {
      $Jobs | Wait-Job -Timeout 90 | Should -HaveCount 3
      $Results = @($Jobs | Receive-Job -ErrorAction Stop)
      $Pool = $Storage['__DumplingsWebDriverLeasePool']

      $Results | Should -HaveCount 3
      @($Results.SessionId | Sort-Object -Unique) | Should -HaveCount 1
      @($Results.Text | Sort-Object) | Should -Be @('1', '2', '3')
      (Get-Process -Id $Pool.ResourceServiceProcessId -ErrorAction Stop).ProcessName | Should -BeExactly 'msedgedriver'
      $Pool.ActiveOwnerId | Should -BeNullOrEmpty

      $Pool.Dispose()
      $Storage.Remove('__DumplingsWebDriverLeasePool')
      @(Get-ChildItem (Join-Path $CachePath 'WebDriver') -Directory -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
      @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'msedge.exe', 'msedgedriver.exe' -and $_.CommandLine -like "*${CachePath}*" }) | Should -BeNullOrEmpty
    } finally {
      $Jobs | Remove-Job -Force -ErrorAction SilentlyContinue
      if ($Storage.ContainsKey('__DumplingsWebDriverLeasePool')) {
        $Storage['__DumplingsWebDriverLeasePool'].Dispose()
        $Storage.Remove('__DumplingsWebDriverLeasePool')
      }
    }
  }

  It 'preempts and recycles a real session when the quantum expires under contention' -Skip:($env:DUMPLINGS_WEBDRIVER_INTEGRATION -ne '1') {
    $ModulePath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'Libraries' 'WebDriver.psm1')).Path
    $Storage = [hashtable]::Synchronized(@{})
    $CachePath = Join-Path $TestDrive 'PreemptionCache'
    $null = New-Item -Path $CachePath -ItemType Directory -Force
    $Owner1 = Start-ThreadJob -ArgumentList $ModulePath, $Storage, $CachePath -ScriptBlock {
      param($Module, $SharedStorage, $SharedCache)

      $Global:DumplingsStorage = $SharedStorage
      $Global:DumplingsPreference = [ordered]@{ WebDriverLeaseDurationSeconds = 1; Timeout = 30 }
      $Global:DumplingsWebDriverLeaseOwnerId = 'preempted-owner'
      $Global:DumplingsCache = $SharedCache
      Import-Module $Module -Force -DisableNameChecking
      $SessionId = Use-EdgeDriver -Headless {
        param($Driver)

        $Session = [string]$Driver.SessionId
        Start-Sleep -Seconds 3
        $Session
      }
      $Outcome = Complete-DumplingsWebDriverLease -OwnerId 'preempted-owner'
      [pscustomobject]@{ Owner = 'preempted-owner'; Outcome = [string]$Outcome.Outcome; SessionId = $SessionId }
    }

    $Owner2 = $null
    try {
      $Deadline = [DateTime]::UtcNow.AddSeconds(30)
      do {
        $Pool = $Storage['__DumplingsWebDriverLeasePool']
        if ($Pool -and $Pool.ActiveOwnerId -eq 'preempted-owner') { break }
        Start-Sleep -Milliseconds 50
      } while ([DateTime]::UtcNow -lt $Deadline)
      $Pool.ActiveOwnerId | Should -BeExactly 'preempted-owner'

      $Owner2 = Start-ThreadJob -ArgumentList $ModulePath, $Storage, $CachePath -ScriptBlock {
        param($Module, $SharedStorage, $SharedCache)

        $Global:DumplingsStorage = $SharedStorage
        $Global:DumplingsPreference = [ordered]@{ WebDriverLeaseDurationSeconds = 1; Timeout = 30 }
        $Global:DumplingsWebDriverLeaseOwnerId = 'waiting-owner'
        $Global:DumplingsCache = $SharedCache
        Import-Module $Module -Force -DisableNameChecking
        $SessionId = Use-EdgeDriver -Headless { param($Driver) [string]$Driver.SessionId }
        $Outcome = Complete-DumplingsWebDriverLease -OwnerId 'waiting-owner'
        [pscustomobject]@{ Owner = 'waiting-owner'; Outcome = [string]$Outcome.Outcome; SessionId = $SessionId }
      }

      @($Owner1, $Owner2) | Wait-Job -Timeout 45 | Should -HaveCount 2
      $Results = @(@($Owner1, $Owner2) | Receive-Job -ErrorAction Stop)
      $Results.Where({ $_.Owner -eq 'preempted-owner' })[0].Outcome | Should -BeExactly 'TimedOut'
      $Results.Where({ $_.Owner -eq 'waiting-owner' })[0].Outcome | Should -BeExactly 'Released'
      @($Results.SessionId | Sort-Object -Unique) | Should -HaveCount 2

      $Storage['__DumplingsWebDriverLeasePool'].Dispose()
      $Storage.Remove('__DumplingsWebDriverLeasePool')
      @(Get-ChildItem (Join-Path $CachePath 'WebDriver') -Directory -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
      @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'msedge.exe', 'msedgedriver.exe' -and $_.CommandLine -like "*${CachePath}*" }) | Should -BeNullOrEmpty
    } finally {
      @($Owner1, $Owner2) | Remove-Job -Force -ErrorAction SilentlyContinue
      if ($Storage.ContainsKey('__DumplingsWebDriverLeasePool')) {
        $Storage['__DumplingsWebDriverLeasePool'].Dispose()
        $Storage.Remove('__DumplingsWebDriverLeasePool')
      }
    }
  }
}
