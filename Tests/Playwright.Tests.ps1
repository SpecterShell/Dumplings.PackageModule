#Requires -Version 7.4

BeforeAll {
  $Script:ModulePath = Join-Path $PSScriptRoot '..' 'Libraries' 'Playwright.psm1'
  $Script:PlaywrightModule = Import-Module $Script:ModulePath -Force -PassThru -DisableNameChecking
}

AfterAll {
  Remove-Module -ModuleInfo $Script:PlaywrightModule -Force -ErrorAction SilentlyContinue
}

Describe 'Playwright synchronous Task boundary' {
  It 'returns Task[T] results without AggregateException wrapping' {
    Wait-PlaywrightTask ([Threading.Tasks.Task]::FromResult([object]'result')) | Should -BeExactly 'result'
  }

  It 'returns no value for a completed non-generic Task' {
    @(Wait-PlaywrightTask ([Threading.Tasks.Task]::CompletedTask)) | Should -HaveCount 0
  }

  It 'preserves the original task exception' {
    $Task = [Threading.Tasks.Task]::FromException([InvalidOperationException]::new('playwright failure'))
    { Wait-PlaywrightTask $Task } | Should -Throw '*playwright failure*'
  }

  It 'bounds a task that does not complete' {
    { Wait-PlaywrightTask ([Threading.Tasks.Task]::Delay(2000)) -TimeoutMilliseconds 20 } |
      Should -Throw '*did not complete*'
  }
}

Describe 'Scoped Playwright PowerShell API' {
  BeforeEach {
    $Global:DumplingsPlaywrightLeaseOwnerId = 'DumplingsWok0/Test.Package/invocation'
    $Script:FakeSession = [pscustomobject]@{
      Page    = 'page'
      Context = 'context'
      Browser = 'browser'
    }
  }

  AfterEach {
    Remove-Variable -Name DumplingsPlaywrightLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  }

  It 'returns script output unchanged and always releases a successful lease' {
    Mock Get-PlaywrightSession { $Script:FakeSession } -ModuleName Playwright
    Mock Exit-PlaywrightLease {} -ModuleName Playwright
    Mock Save-PlaywrightScreenshot {} -ModuleName Playwright

    $Result = @(Use-PlaywrightPage -Headless { param($Page, $Context, $Browser, $Session) "${Page}:${Context}"; $Browser })

    $Result | Should -Be @('page:context', 'browser')
    Should -Invoke Exit-PlaywrightLease -ModuleName Playwright -Times 1 -ParameterFilter { -not $Failed }
    Should -Invoke Save-PlaywrightScreenshot -ModuleName Playwright -Times 0
  }

  It 'captures failure evidence before recycling and preserves the script error' {
    Mock Get-PlaywrightSession { $Script:FakeSession } -ModuleName Playwright
    Mock Exit-PlaywrightLease {} -ModuleName Playwright
    Mock Save-PlaywrightScreenshot { 'failure.png' } -ModuleName Playwright

    { Use-PlaywrightPage -Screenshot { throw 'script failure' } } | Should -Throw '*script failure*'

    Should -Invoke Save-PlaywrightScreenshot -ModuleName Playwright -Times 1 -ParameterFilter { $Failed }
    Should -Invoke Exit-PlaywrightLease -ModuleName Playwright -Times 1 -ParameterFilter { $Failed }
  }

  It 'does not blame the browser lease for a downstream pipeline failure' {
    Mock Get-PlaywrightSession { $Script:FakeSession } -ModuleName Playwright
    Mock Exit-PlaywrightLease {} -ModuleName Playwright

    { Use-PlaywrightPage { '{invalid json' } | ConvertFrom-Json -ErrorAction Stop } |
      Should -Throw

    Should -Invoke Exit-PlaywrightLease -ModuleName Playwright -Times 1 -ParameterFilter { -not $Failed }
  }

  It 'does not expose a PowerShell route or event callback path' {
    $ModuleSource = Get-Content -LiteralPath $Script:ModulePath -Raw
    $SessionSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'Assets' 'Source' 'Playwright' 'PlaywrightSession.cs') -Raw

    $ModuleSource | Should -Not -Match '(?is)RouteAsync\s*\([^\)]*\[scriptblock\]'
    $SessionSource | Should -Match 'Func<IRoute,Task>|HandleRouteAsync'
    $SessionSource | Should -Not -Match 'System\.Management\.Automation|\[scriptblock\]'
  }

  It 'passes StealthyFetcher-compatible context controls to the pooled lease' {
    Mock Get-PlaywrightLease { [pscustomobject]@{ Driver = 'stealth-session' } } -ModuleName Playwright

    $Result = Get-PlaywrightSession -Stealth -Headless -DisableResources -BlockedDomain 'example.com' `
      -Locale 'en-US' -TimezoneId 'Asia/Singapore' -BlockWebRTC

    $Result | Should -BeExactly 'stealth-session'
    Should -Invoke Get-PlaywrightLease -ModuleName Playwright -Times 1 -ParameterFilter {
      $Stealth -and $Headless -and $DisableResources -and $BlockWebRTC -and
      $BlockedDomain -contains 'example.com' -and $Locale -eq 'en-US' -and $TimezoneId -eq 'Asia/Singapore'
    }
  }

  It 'detects supported Cloudflare challenge markup without a browser callback' {
    & $Script:PlaywrightModule {
      Get-PlaywrightCloudflareChallengeType -Content "<script>window._cf_chl_opt={cType: 'interactive'}</script>"
    } | Should -BeExactly 'interactive'

    & $Script:PlaywrightModule {
      Get-PlaywrightCloudflareChallengeType -Content '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
    } | Should -BeExactly 'embedded'

    & $Script:PlaywrightModule {
      Get-PlaywrightCloudflareChallengeType -Content '<main>ordinary content</main>'
    } | Should -BeNullOrEmpty
  }

  It 'calculates a bounded click point for a locator-invisible Turnstile checkbox' {
    $Point = & $Script:PlaywrightModule {
      Get-PlaywrightCloudflareFrameClickPoint -BoundingBox ([pscustomobject]@{
          X      = 512.0
          Y      = 304.0
          Width  = 300.0
          Height = 65.0
        })
    }

    $Point.X | Should -Be 28.0
    $Point.Y | Should -Be 32.5
    & $Script:PlaywrightModule {
      Get-PlaywrightCloudflareFrameClickPoint -BoundingBox ([pscustomobject]@{ X = 0; Y = 0; Width = 0; Height = 65 })
    } | Should -BeNullOrEmpty
  }

  It 'uses Patchright source-grounded command leak controls only for stealth sessions' {
    $SessionSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'Assets' 'Source' 'Playwright' 'PlaywrightSession.cs') -Raw

    $SessionSource | Should -Match 'PatchrightIgnoredChromiumArguments'
    $SessionSource | Should -Match '--disable-blink-features=AutomationControlled'
    $SessionSource | Should -Match '--webrtc-ip-handling-policy=disable_non_proxied_udp'
  }

  It 'validates fetch-only stealth settings before acquiring a browser' {
    { Invoke-PlaywrightFetch https://example.com/ -SolveCloudflare -MaximumRetryCount 1 } |
      Should -Throw '*requires*Stealth*'
    { Invoke-PlaywrightFetch https://example.com/ -CaptureXhr '[' -MaximumRetryCount 1 } |
      Should -Throw '*valid regular expression*'
  }
}

Describe 'Playwright runner lifecycle hooks' {
  BeforeEach {
    $Global:DumplingsStorage = [hashtable]::Synchronized(@{})
    $Global:DumplingsPreference = [ordered]@{ PlaywrightLeaseDurationSeconds = 30; Timeout = 60 }
    $Script:Context = [ordered]@{
      Storage      = $Global:DumplingsStorage
      WorkerName   = 'DumplingsWok0'
      TaskName     = 'Test.Package'
      InvocationId = 'invocation'
      Task         = [pscustomobject]@{ InvocationSucceeded = $true; InvocationSkipped = $false }
      Items        = [ordered]@{}
    }
  }

  AfterEach {
    if ($Global:DumplingsStorage.ContainsKey('__DumplingsPlaywrightLeasePool')) {
      $Global:DumplingsStorage['__DumplingsPlaywrightLeasePool'].Dispose()
      $Global:DumplingsStorage.Remove('__DumplingsPlaywrightLeasePool')
    }
    Remove-Variable -Name DumplingsPlaywrightLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  }

  It 'assigns and clears the same task owner without creating an unused pool' {
    & (Join-Path $PSScriptRoot '..' 'Hooks' 'BeforeTask.ps1') -Context $Script:Context
    $Global:DumplingsPlaywrightLeaseOwnerId | Should -BeExactly 'DumplingsWok0/Test.Package/invocation'

    & (Join-Path $PSScriptRoot '..' 'Hooks' 'AfterTask.ps1') -Context $Script:Context

    $Global:DumplingsStorage.ContainsKey('__DumplingsPlaywrightLeasePool') | Should -BeFalse
    Get-Variable DumplingsPlaywrightLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
  }

  It 'disposes a Playwright pool during final runner shutdown' {
    $Pool = [IO.MemoryStream]::new()
    $Global:DumplingsStorage['__DumplingsPlaywrightLeasePool'] = $Pool

    & (Join-Path $PSScriptRoot '..' 'Hooks' 'RunnerStopping.ps1') -Context $Script:Context

    $Pool.CanRead | Should -BeFalse
    $Global:DumplingsStorage.ContainsKey('__DumplingsPlaywrightLeasePool') | Should -BeFalse
  }

  It 'marks a successful task failed after Playwright lease preemption' {
    Mock Complete-DumplingsPlaywrightLease {
      [pscustomobject]@{ Outcome = 'TimedOut'; Message = 'lease expired under contention' }
    }
    & (Join-Path $PSScriptRoot '..' 'Hooks' 'BeforeTask.ps1') -Context $Script:Context

    { & (Join-Path $PSScriptRoot '..' 'Hooks' 'AfterTask.ps1') -Context $Script:Context } |
      Should -Throw '*Test.Package*Playwright*TimedOut*'

    $Script:Context.Task.InvocationSucceeded | Should -BeFalse
    $Script:Context.Task.InvocationSkipped | Should -BeFalse
  }
}

Describe 'Playwright task integration contract' {
  It 'requires task scripts to use the scoped API' {
    $TaskRoot = Join-Path $PSScriptRoot '..' '..' '..' 'Tasks'
    $Violations = Get-ChildItem -LiteralPath $TaskRoot -Filter 'Script*.ps1' -File -Recurse |
      Select-String -Pattern '\bGet-Playwright(?:Session|Page)\b|\.RouteAsync\s*\('
    $Violations | Should -BeNullOrEmpty
  }

  It 'contains no task-side Selenium dependencies after migration' {
    $TaskRoot = Join-Path $PSScriptRoot '..' '..' '..' 'Tasks'
    $Violations = Get-ChildItem -LiteralPath $TaskRoot -Filter 'Script*.ps1' -File -Recurse |
      Select-String -Pattern '\b(?:Use|Get|New)-(?:Edge|Firefox)Driver\b|OpenQA\.Selenium|\bWebDriverWait\b'
    $Violations | Should -BeNullOrEmpty
  }
}

Describe 'Shared Playwright real runspace smoke' -Tag Integration {
  It 'reuses one browser across isolated task contexts without async PowerShell callbacks' -Skip:($env:DUMPLINGS_PLAYWRIGHT_INTEGRATION -ne '1') {
    $RuntimePath = $env:DUMPLINGS_PLAYWRIGHT_RUNTIME_PATH
    if ([string]::IsNullOrWhiteSpace($RuntimePath)) { throw 'DUMPLINGS_PLAYWRIGHT_RUNTIME_PATH is required for integration tests.' }
    $Storage = [hashtable]::Synchronized(@{})
    $Jobs = foreach ($Index in 1..3) {
      Start-ThreadJob -ArgumentList $Script:ModulePath, $RuntimePath, $Storage, $Index -ScriptBlock {
        param($ModulePath, $RuntimePath, $SharedStorage, $Number)
        $env:DUMPLINGS_PLAYWRIGHT_RUNTIME_PATH = $RuntimePath
        $Global:DumplingsStorage = $SharedStorage
        $Global:DumplingsPreference = [ordered]@{ PlaywrightLeaseDurationSeconds = 30; Timeout = 60 }
        $Global:DumplingsPlaywrightLeaseOwnerId = "integration-${Number}"
        Import-Module $ModulePath -Force -DisableNameChecking
        $Result = Use-PlaywrightPage -Stealth -Headless {
          param($Page, $Context, $Browser)
          # The image is aborted by the compiled C# route callback. Completion
          # verifies that Playwright never tries to invoke PowerShell asynchronously.
          $null = Wait-PlaywrightTask ($Page.GotoAsync("data:text/html,<main id='ready'>${Number}</main><img src='https://example.invalid/blocked.png'>"))
          [pscustomobject]@{
            BrowserVersion = $Browser.Version
            Text           = Wait-PlaywrightTask ($Page.Locator('#ready').TextContentAsync())
            WebDriver      = Wait-PlaywrightTask ($Page.EvaluateAsync[object]('() => navigator.webdriver', $null))
          }
        }
        $null = Complete-DumplingsPlaywrightLease -OwnerId "integration-${Number}"
        $Result
      }
    }

    try {
      $Jobs | Wait-Job -Timeout 90 | Should -HaveCount 3
      $Results = @($Jobs | Receive-Job -ErrorAction Stop)
      @($Results.Text | Sort-Object) | Should -Be @('1', '2', '3')
      @($Results.BrowserVersion | Sort-Object -Unique) | Should -HaveCount 1
      @($Results.WebDriver | Where-Object { $_ }) | Should -HaveCount 0
      $Pool = $Storage['__DumplingsPlaywrightLeasePool']
      $Pool.ActiveOwnerId | Should -BeNullOrEmpty
      $DriverProcessId = $Pool.ResourceServiceProcessId
      $DriverProcessId | Should -BeGreaterThan 0
      (Get-Process -Id $DriverProcessId -ErrorAction Stop).ProcessName | Should -BeExactly 'node'

      $Pool.Dispose()
      $Storage.Remove('__DumplingsPlaywrightLeasePool')
      $Deadline = [DateTime]::UtcNow.AddSeconds(10)
      while ((Get-Process -Id $DriverProcessId -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $Deadline) {
        Start-Sleep -Milliseconds 100
      }
      Get-Process -Id $DriverProcessId -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    } finally {
      $Jobs | Remove-Job -Force -ErrorAction SilentlyContinue
      if ($Storage.ContainsKey('__DumplingsPlaywrightLeasePool')) {
        $Storage['__DumplingsPlaywrightLeasePool'].Dispose()
        $Storage.Remove('__DumplingsPlaywrightLeasePool')
      }
    }
  }
}
