BeforeAll { . (Join-Path $PSScriptRoot '..\..\Hooks\Browser.Common.ps1') }

Describe 'Browser broker cleanup ownership' -Tag Unit {
  It 'disposes outside the shared lock and retains a closed broker until forced workers stop' {
    $Storage = [hashtable]::Synchronized(@{})
    $Pool = [pscustomobject]@{ Storage = $Storage; Disposed = $false }
    $Pool | Add-Member ScriptMethod Dispose {
      if ([Threading.Monitor]::IsEntered($this.Storage.SyncRoot)) { throw 'Disposal held the global lock' }
      $this.Disposed = $true
    }
    $Storage['__DumplingsWebDriverLeasePool'] = $Pool
    Close-DumplingsBrowserHookPool -Storage $Storage -Name WebDriver -KeepInStorage
    $Pool.Disposed | Should -BeTrue
    $Storage.ContainsKey('__DumplingsWebDriverLeasePool') | Should -BeTrue
    Close-DumplingsBrowserHookPool -Storage $Storage -Name WebDriver
    $Storage.ContainsKey('__DumplingsWebDriverLeasePool') | Should -BeFalse
  }

  It 'removes a failing broker without deleting another broker' {
    $Storage = [hashtable]::Synchronized(@{})
    $Pool = [pscustomobject]@{}
    $Pool | Add-Member ScriptMethod Dispose { throw 'Expected disposal failure' }
    $Storage['__DumplingsWebDriverLeasePool'] = $Pool
    $Storage['__DumplingsPlaywrightLeasePool'] = 'unrelated'
    { Close-DumplingsBrowserHookPool -Storage $Storage -Name WebDriver } | Should -Throw '*Expected disposal failure*'
    $Storage.ContainsKey('__DumplingsWebDriverLeasePool') | Should -BeFalse
    $Storage['__DumplingsPlaywrightLeasePool'] | Should -Be 'unrelated'
  }
}
