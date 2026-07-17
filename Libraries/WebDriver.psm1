# SPDX-License-Identifier: MIT

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:WebDriverPoolStorageKey = '__DumplingsWebDriverLeasePool'
$Script:WebDriverLeaseDurationSeconds = 30
$Script:StandaloneWebDriverPool = $null
$Script:WebDriverLeases = $null

function Get-WebDriverAssembly {
  <#
  .SYNOPSIS
    Get the WebDriver.dll assembly
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -LiteralPath ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'WebDriver.dll')) {
    return (Get-Item -LiteralPath $Path -Force).FullName
  }
  throw 'The WebDriver.dll assembly could not be found'
}

function Import-WebDriverAssembly {
  <#
  .SYNOPSIS
    Load the Selenium WebDriver assembly once per process
  #>
  param ()

  if (-not ([System.Management.Automation.PSTypeName]'OpenQA.Selenium.WebDriver').Type) {
    Add-Type -Path (Get-WebDriverAssembly)
  }
}

function Import-WebDriverLeaseBroker {
  <#
  .SYNOPSIS
    Load the process-wide WebDriver lease broker once across worker runspaces
  #>
  param ()

  if (([System.Management.Automation.PSTypeName]'Dumplings.WebDriver.WebDriverLeasePool').Type) { return }

  $Mutex = [Threading.Mutex]::new($false, 'Local\Dumplings-WebDriverLeaseBroker')
  $HasLock = $false
  try {
    try { $HasLock = $Mutex.WaitOne([timespan]::FromMinutes(2)) } catch [Threading.AbandonedMutexException] { $HasLock = $true }
    if (-not $HasLock) { throw 'Timed out while loading the WebDriver lease broker' }
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.WebDriver.WebDriverLeasePool').Type) {
      Add-Type -Path (Join-Path $PSScriptRoot '..' 'Assets' 'WebDriverLeasePool.cs')
    }
  } finally {
    if ($HasLock) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}

Import-WebDriverAssembly
Import-WebDriverLeaseBroker

# Initialize typed state only after both assemblies have loaded.
$Script:WebDriverLeases = [System.Collections.Concurrent.ConcurrentDictionary[string, Dumplings.WebDriver.WebDriverLease]]::new([StringComparer]::Ordinal)

function Get-WebDriverLeaseDuration {
  <#
  .SYNOPSIS
    Get the configured contention quantum for one task
  #>
  [OutputType([timespan])]
  param ()

  $Seconds = $Script:WebDriverLeaseDurationSeconds
  $PreferenceVariable = Get-Variable -Name DumplingsPreference -Scope Global -ErrorAction SilentlyContinue
  if ($PreferenceVariable -and $PreferenceVariable.Value -is [Collections.IDictionary] -and $PreferenceVariable.Value.Contains('WebDriverLeaseDurationSeconds')) {
    $ConfiguredSeconds = 0
    if ([int]::TryParse([string]$PreferenceVariable.Value.WebDriverLeaseDurationSeconds, [ref]$ConfiguredSeconds) -and $ConfiguredSeconds -gt 0) {
      $Seconds = $ConfiguredSeconds
    }
  }
  return [timespan]::FromSeconds($Seconds)
}

function Get-WebDriverQueueTimeout {
  <#
  .SYNOPSIS
    Bound queue waits by the existing Dumplings run timeout
  #>
  [OutputType([timespan])]
  param ()

  $PreferenceVariable = Get-Variable -Name DumplingsPreference -Scope Global -ErrorAction SilentlyContinue
  if ($PreferenceVariable -and $PreferenceVariable.Value -is [Collections.IDictionary] -and $PreferenceVariable.Value.Contains('Timeout')) {
    $Seconds = 0
    if ([int]::TryParse([string]$PreferenceVariable.Value.Timeout, [ref]$Seconds) -and $Seconds -gt 0) {
      return [timespan]::FromSeconds($Seconds)
    }
  }
  return [Threading.Timeout]::InfiniteTimeSpan
}

function Get-WebDriverLeaseOwnerId {
  <#
  .SYNOPSIS
    Resolve the current task invocation or standalone runspace as the lease owner
  #>
  [OutputType([string])]
  param ()

  $OwnerVariable = Get-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  if ($OwnerVariable -and $OwnerVariable.Value) { return [string]$OwnerVariable.Value }
  $RunspaceId = [runspace]::DefaultRunspace.InstanceId
  return "Runspace:${RunspaceId}"
}

function Get-WebDriverLeasePool {
  <#
  .SYNOPSIS
    Return the process-wide shared pool, or a module-local pool outside Dumplings
  #>
  [OutputType([Dumplings.WebDriver.WebDriverLeasePool])]
  param ([switch]$ExistingOnly)

  $StorageVariable = Get-Variable -Name DumplingsStorage -Scope Global -ErrorAction SilentlyContinue
  $Storage = if ($StorageVariable) { $StorageVariable.Value } else { $null }
  if ($Storage -is [hashtable] -and $Storage.IsSynchronized) {
    [Threading.Monitor]::Enter($Storage.SyncRoot)
    try {
      if (-not $Storage.ContainsKey($Script:WebDriverPoolStorageKey)) {
        if ($ExistingOnly) { return $null }
        $Storage[$Script:WebDriverPoolStorageKey] = [Dumplings.WebDriver.WebDriverLeasePool]::new()
      }
      return $Storage[$Script:WebDriverPoolStorageKey]
    } finally {
      [Threading.Monitor]::Exit($Storage.SyncRoot)
    }
  }

  if ($ExistingOnly -and -not $Script:StandaloneWebDriverPool) { return $null }
  if (-not $Script:StandaloneWebDriverPool) {
    $Script:StandaloneWebDriverPool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
  }
  return $Script:StandaloneWebDriverPool
}

function New-WebDriverProfileDirectory {
  <#
  .SYNOPSIS
    Create a profile directory whose lifecycle follows the pooled browser session
  #>
  [OutputType([string])]
  param ()

  $CacheVariable = Get-Variable -Name DumplingsCache -Scope Global -ErrorAction SilentlyContinue
  $Root = if ($CacheVariable -and $CacheVariable.Value) { Join-Path $CacheVariable.Value 'WebDriver' } else { Join-Path ([IO.Path]::GetTempPath()) 'Dumplings-WebDriver' }
  $null = New-Item -Path $Root -ItemType Directory -Force
  return (New-Item -Path $Root -Name ([guid]::NewGuid().ToString('N')) -ItemType Directory -Force).FullName
}

function Resolve-WebDriverExecutablePath {
  <#
  .SYNOPSIS
    Resolve an executable, directory-valued CI variable, or Scoop shim to the real driver executable
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ExecutableName
  )

  if (Test-Path -LiteralPath $Path -PathType Container) { $Path = Join-Path $Path $ExecutableName }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "The WebDriver executable does not exist: ${Path}" }

  $ShimPath = [IO.Path]::ChangeExtension($Path, '.shim')
  if (Test-Path -LiteralPath $ShimPath -PathType Leaf) {
    $ShimConfig = Get-Content -LiteralPath $ShimPath -Raw
    if ($ShimConfig -match '(?m)^\s*path\s*=\s*"(?<Path>[^"]+)"' -and (Test-Path -LiteralPath $Matches.Path -PathType Leaf)) {
      $Path = $Matches.Path
    }
  }
  return (Get-Item -LiteralPath $Path -Force).FullName
}

function Get-EdgeDriverExecutablePath {
  <#
  .SYNOPSIS
    Get the path of the EdgeDriver executable
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -LiteralPath Env:\EDGEWEBDRIVER) {
    return Resolve-WebDriverExecutablePath -Path $Env:EDGEWEBDRIVER -ExecutableName 'msedgedriver.exe'
  }
  if ($Command = Get-Command -Name 'msedgedriver.exe' -ErrorAction SilentlyContinue) {
    return Resolve-WebDriverExecutablePath -Path $Command.Path -ExecutableName 'msedgedriver.exe'
  }
  throw 'Could not find msedgedriver.exe'
}

function New-EdgeDriverOption {
  <#
  .SYNOPSIS
    Create consistent Edge options for unmanaged and pooled sessions
  #>
  [OutputType([OpenQA.Selenium.Edge.EdgeOptions])]
  param (
    [switch]$Headless,
    [string]$ProfilePath
  )

  $Options = [OpenQA.Selenium.Edge.EdgeOptions]::new()
  if ($Headless) { $Options.AddArgument('--headless=new') }
  if ($ProfilePath) { $Options.AddArgument("--user-data-dir=${ProfilePath}") }
  $Options.AddArgument('--disable-blink-features=AutomationControlled')
  $Options.AddUserProfilePreference('profile.managed_default_content_settings.images', 2)
  return $Options
}

function Initialize-EdgeDriver {
  <#
  .SYNOPSIS
    Apply the browser behavior shared by managed and unmanaged Edge sessions
  #>
  param ([Parameter(Mandatory)][OpenQA.Selenium.Edge.EdgeDriver]$Driver)

  $Driver.Manage().Window.Size = [Drawing.Size]::new(1920, 1080)
  $Parameters = [Collections.Generic.Dictionary[string, object]]::new()
  $Parameters.Add('urls', @('*.jpg*', '*.jpeg*', '*.bmp*', '*.png*', '*.webp*', '*.gif*', '*.svg*', '*.mp4*', '*.webm*', '*.flv*'))
  $null = $Driver.ExecuteCdpCommand('Network.setBlockedURLs', $Parameters)
  $null = $Driver.ExecuteCdpCommand('Network.enable', [Collections.Generic.Dictionary[string, object]]::new())
}

function New-EdgeDriver {
  <#
  .SYNOPSIS
    Create an unmanaged EdgeDriver instance
  .DESCRIPTION
    Dumplings task scripts must use Use-EdgeDriver or Get-EdgeDriver so the process-wide lease is enforced.
  #>
  [OutputType([OpenQA.Selenium.Edge.EdgeDriver])]
  param ([switch]$Headless)

  $Driver = [OpenQA.Selenium.Edge.EdgeDriver]::new((Get-EdgeDriverExecutablePath), (New-EdgeDriverOption -Headless:$Headless))
  Initialize-EdgeDriver -Driver $Driver
  return $Driver
}

function New-PooledEdgeDriverResource {
  <#
  .SYNOPSIS
    Create the Edge session, service, and profile owned by the shared broker
  #>
  [OutputType([Dumplings.WebDriver.WebDriverResource])]
  param (
    [Parameter(Mandatory)][string]$Configuration,
    [switch]$Headless
  )

  $ExecutablePath = Get-EdgeDriverExecutablePath
  $ProfilePath = New-WebDriverProfileDirectory
  $Service = [OpenQA.Selenium.Edge.EdgeDriverService]::CreateDefaultService((Split-Path $ExecutablePath), (Split-Path $ExecutablePath -Leaf))
  $Service.HideCommandPromptWindow = $true
  $Driver = $null
  try {
    $Driver = [OpenQA.Selenium.Edge.EdgeDriver]::new($Service, (New-EdgeDriverOption -Headless:$Headless -ProfilePath $ProfilePath), [timespan]::FromSeconds(60))
    Initialize-EdgeDriver -Driver $Driver
    return [Dumplings.WebDriver.WebDriverResource]::new($Driver, $Service, $Service.ProcessId, $Configuration, [string[]]@($ProfilePath))
  } catch {
    if ($Driver) { $Driver.Dispose() }
    $Service.Dispose()
    Remove-Item -LiteralPath $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue
    throw
  }
}

function Get-FirefoxDriverExecutablePath {
  <#
  .SYNOPSIS
    Get the path of the FirefoxDriver executable
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -LiteralPath Env:\GECKOWEBDRIVER) {
    return Resolve-WebDriverExecutablePath -Path $Env:GECKOWEBDRIVER -ExecutableName 'geckodriver.exe'
  }
  if ($Command = Get-Command -Name 'geckodriver.exe' -ErrorAction SilentlyContinue) {
    return Resolve-WebDriverExecutablePath -Path $Command.Path -ExecutableName 'geckodriver.exe'
  }
  throw 'Could not find geckodriver.exe'
}

function New-FirefoxDriverOption {
  <#
  .SYNOPSIS
    Create consistent Firefox options for unmanaged and pooled sessions
  #>
  [OutputType([OpenQA.Selenium.Firefox.FirefoxOptions])]
  param (
    [switch]$Headless,
    [string]$ProfilePath
  )

  $Options = [OpenQA.Selenium.Firefox.FirefoxOptions]::new()
  if ($Headless) { $Options.AddArgument('--headless') }
  if ($ProfilePath) {
    $Options.AddArgument('-profile')
    $Options.AddArgument($ProfilePath)
  }
  $Options.SetPreference('permissions.default.image', 2)
  # GeckoDriver has no cache-clearing WebDriver endpoint, so pooled Firefox sessions never retain a browser cache.
  $Options.SetPreference('browser.cache.disk.enable', $false)
  $Options.SetPreference('browser.cache.memory.enable', $false)
  $Options.SetPreference('browser.cache.offline.enable', $false)
  $Options.SetPreference('network.http.use-cache', $false)
  return $Options
}

function New-FirefoxDriver {
  <#
  .SYNOPSIS
    Create an unmanaged FirefoxDriver instance
  .DESCRIPTION
    Dumplings task scripts must use Use-FirefoxDriver or Get-FirefoxDriver so the process-wide lease is enforced.
  #>
  [OutputType([OpenQA.Selenium.Firefox.FirefoxDriver])]
  param ([switch]$Headless)

  $Driver = [OpenQA.Selenium.Firefox.FirefoxDriver]::new((Get-FirefoxDriverExecutablePath), (New-FirefoxDriverOption -Headless:$Headless))
  $Driver.Manage().Window.Size = [Drawing.Size]::new(1920, 1080)
  return $Driver
}

function New-PooledFirefoxDriverResource {
  <#
  .SYNOPSIS
    Create the Firefox session, service, and profile owned by the shared broker
  #>
  [OutputType([Dumplings.WebDriver.WebDriverResource])]
  param (
    [Parameter(Mandatory)][string]$Configuration,
    [switch]$Headless
  )

  $ExecutablePath = Get-FirefoxDriverExecutablePath
  $ProfilePath = New-WebDriverProfileDirectory
  $Service = [OpenQA.Selenium.Firefox.FirefoxDriverService]::CreateDefaultService((Split-Path $ExecutablePath), (Split-Path $ExecutablePath -Leaf))
  $Service.HideCommandPromptWindow = $true
  $Driver = $null
  try {
    $Driver = [OpenQA.Selenium.Firefox.FirefoxDriver]::new($Service, (New-FirefoxDriverOption -Headless:$Headless -ProfilePath $ProfilePath), [timespan]::FromSeconds(60))
    $Driver.Manage().Window.Size = [Drawing.Size]::new(1920, 1080)
    return [Dumplings.WebDriver.WebDriverResource]::new($Driver, $Service, $Service.ProcessId, $Configuration, [string[]]@($ProfilePath))
  } catch {
    if ($Driver) { $Driver.Dispose() }
    $Service.Dispose()
    Remove-Item -LiteralPath $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue
    throw
  }
}

function Get-WebDriverLease {
  <#
  .SYNOPSIS
    Acquire the sole process-wide browser session under the current task owner
  #>
  [OutputType([Dumplings.WebDriver.WebDriverLease])]
  param (
    [Parameter(Mandatory)][ValidateSet('Edge', 'Firefox')][string]$Browser,
    [switch]$Headless
  )

  $OwnerId = Get-WebDriverLeaseOwnerId
  $Configuration = "${Browser}:$(if ($Headless) { 'Headless' } else { 'Visible' })"
  $Pool = Get-WebDriverLeasePool
  $ResourceFactory = $Browser -eq 'Edge' ? ${function:New-PooledEdgeDriverResource} : ${function:New-PooledFirefoxDriverResource}
  $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] { & $ResourceFactory -Configuration $Configuration -Headless:$Headless }.GetNewClosure()
  $Lease = $Pool.Acquire($OwnerId, $Configuration, $Factory, (Get-WebDriverLeaseDuration), (Get-WebDriverQueueTimeout))
  $Script:WebDriverLeases[$OwnerId] = $Lease
  return $Lease
}

function Get-EdgeDriver {
  <#
  .SYNOPSIS
    Acquire and return the process-wide managed EdgeDriver instance
  #>
  [OutputType([OpenQA.Selenium.Edge.EdgeDriver])]
  param ([switch]$Headless)

  return [OpenQA.Selenium.Edge.EdgeDriver](Get-WebDriverLease -Browser Edge -Headless:$Headless).Driver
}

function Get-FirefoxDriver {
  <#
  .SYNOPSIS
    Acquire and return the process-wide managed FirefoxDriver instance
  #>
  [OutputType([OpenQA.Selenium.Firefox.FirefoxDriver])]
  param ([switch]$Headless)

  return [OpenQA.Selenium.Firefox.FirefoxDriver](Get-WebDriverLease -Browser Firefox -Headless:$Headless).Driver
}

function Reset-WebDriverSession {
  <#
  .SYNOPSIS
    Remove task-specific browser state before a healthy session is reused
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][Dumplings.WebDriver.WebDriverLease]$Lease)

  try {
    $Driver = $Lease.Driver
    $WindowHandles = @($Driver.WindowHandles)
    if ($WindowHandles.Count -gt 0) {
      $PrimaryWindow = $WindowHandles[0]
      foreach ($WindowHandle in $WindowHandles | Select-Object -Skip 1) {
        $null = $Driver.SwitchTo().Window($WindowHandle)
        $Driver.Close()
      }
      $null = $Driver.SwitchTo().Window($PrimaryWindow)
    }

    if ($Lease.Configuration.StartsWith('Edge:', [StringComparison]::Ordinal)) {
      $Driver = [OpenQA.Selenium.Edge.EdgeDriver]$Lease.Driver
      $null = $Driver.ExecuteCdpCommand('Network.clearBrowserCache', [Collections.Generic.Dictionary[string, object]]::new())
      $null = $Driver.ExecuteCdpCommand('Network.clearBrowserCookies', [Collections.Generic.Dictionary[string, object]]::new())
    } else {
      $Driver = [OpenQA.Selenium.Firefox.FirefoxDriver]$Lease.Driver
      $Driver.Manage().Cookies.DeleteAllCookies()
    }
    $Driver.Navigate().GoToUrl('about:blank')
    return $true
  } catch {
    return $false
  }
}

function Exit-WebDriverLease {
  <#
  .SYNOPSIS
    Release or recycle the current task's managed WebDriver lease
  #>
  [OutputType([Dumplings.WebDriver.WebDriverLeaseOutcomeRecord])]
  param (
    [string]$OwnerId = (Get-WebDriverLeaseOwnerId),
    [switch]$Failed,
    [switch]$Recycle
  )

  $Pool = Get-WebDriverLeasePool -ExistingOnly
  if (-not $Pool) {
    $RemovedLease = $null
    $null = $Script:WebDriverLeases.TryRemove($OwnerId, [ref]$RemovedLease)
    return
  }
  $Lease = $Pool.GetActiveLease($OwnerId)
  $ResetFailed = $false
  if ($Lease -and -not $Failed -and -not $Recycle) {
    $ResetFailed = -not (Reset-WebDriverSession -Lease $Lease)
  }

  if ($Lease) {
    $ShouldRecycle = $Failed -or $Recycle -or $ResetFailed
    $Outcome = if ($Failed -or $ResetFailed) { [Dumplings.WebDriver.WebDriverLeaseOutcome]::Failed } elseif ($Recycle) { [Dumplings.WebDriver.WebDriverLeaseOutcome]::Stopped } else { [Dumplings.WebDriver.WebDriverLeaseOutcome]::Released }
    $Message = if ($ResetFailed) { 'The WebDriver session reset failed and the session was recycled.' } elseif ($Failed) { 'The task failed while holding the WebDriver lease.' } elseif ($Recycle) { 'The WebDriver lease was stopped and recycled.' } else { 'The WebDriver lease was released.' }
    $null = $Pool.Release($OwnerId, $Lease.Generation, $Outcome, $ShouldRecycle, $Message)
  }

  $RemovedLease = $null
  $null = $Script:WebDriverLeases.TryRemove($OwnerId, [ref]$RemovedLease)
  $Result = $Pool.GetOutcome($OwnerId)
  if ($ResetFailed) { throw 'The shared WebDriver session could not be reset and was recycled.' }
  return $Result
}

function Use-EdgeDriver {
  <#
  .SYNOPSIS
    Run a script block with the leased EdgeDriver and release it in finally
  #>
  param (
    [switch]$Headless,
    [Parameter(Mandatory, Position = 0)][scriptblock]$ScriptBlock
  )

  $OwnerId = Get-WebDriverLeaseOwnerId
  $Succeeded = $false
  try {
    $Driver = Get-EdgeDriver -Headless:$Headless
    & $ScriptBlock $Driver
    $Succeeded = $true
  } finally {
    $null = Exit-WebDriverLease -OwnerId $OwnerId -Failed:(-not $Succeeded)
  }
}

function Use-FirefoxDriver {
  <#
  .SYNOPSIS
    Run a script block with the leased FirefoxDriver and release it in finally
  #>
  param (
    [switch]$Headless,
    [Parameter(Mandatory, Position = 0)][scriptblock]$ScriptBlock
  )

  $OwnerId = Get-WebDriverLeaseOwnerId
  $Succeeded = $false
  try {
    $Driver = Get-FirefoxDriver -Headless:$Headless
    & $ScriptBlock $Driver
    $Succeeded = $true
  } finally {
    $null = Exit-WebDriverLease -OwnerId $OwnerId -Failed:(-not $Succeeded)
  }
}

function Stop-EdgeDriver {
  <#
  .SYNOPSIS
    Stop and recycle the current task's managed EdgeDriver session
  #>
  param ()

  $OwnerId = Get-WebDriverLeaseOwnerId
  $Pool = Get-WebDriverLeasePool -ExistingOnly
  if (-not $Pool) { return }
  $Lease = $Pool.GetActiveLease($OwnerId)
  if ($Lease -and $Lease.Configuration.StartsWith('Edge:', [StringComparison]::Ordinal)) {
    $null = Exit-WebDriverLease -OwnerId $OwnerId -Recycle
  }
}

function Stop-FirefoxDriver {
  <#
  .SYNOPSIS
    Stop and recycle the current task's managed FirefoxDriver session
  #>
  param ()

  $OwnerId = Get-WebDriverLeaseOwnerId
  $Pool = Get-WebDriverLeasePool -ExistingOnly
  if (-not $Pool) { return }
  $Lease = $Pool.GetActiveLease($OwnerId)
  if ($Lease -and $Lease.Configuration.StartsWith('Firefox:', [StringComparison]::Ordinal)) {
    $null = Exit-WebDriverLease -OwnerId $OwnerId -Recycle
  }
}

function Complete-DumplingsWebDriverLease {
  <#
  .SYNOPSIS
    Complete a task lease and return its terminal outcome to the runner
  #>
  [OutputType([Dumplings.WebDriver.WebDriverLeaseOutcomeRecord])]
  param (
    [Parameter(Mandatory)][string]$OwnerId,
    [switch]$Failed
  )

  $Pool = Get-WebDriverLeasePool -ExistingOnly
  if (-not $Pool) { return }
  if ($Pool.GetActiveLease($OwnerId)) {
    $null = Exit-WebDriverLease -OwnerId $OwnerId -Failed:$Failed
  }
  $RemovedLease = $null
  $null = $Script:WebDriverLeases.TryRemove($OwnerId, [ref]$RemovedLease)
  return $Pool.TakeOutcome($OwnerId)
}

# Worker module unload must not dispose the process-wide pool. The coordinator owns it.
$ExecutionContext.SessionState.Module.OnRemove += {
  $OwnerVariable = Get-Variable -Name DumplingsWebDriverLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  if ($OwnerVariable -and $OwnerVariable.Value) {
    try { $null = Complete-DumplingsWebDriverLease -OwnerId $OwnerVariable.Value -Failed } catch {}
  }
  if ($Script:StandaloneWebDriverPool) {
    $Script:StandaloneWebDriverPool.Dispose()
    $Script:StandaloneWebDriverPool = $null
  }
}

Export-ModuleMember -Function New-EdgeDriver, Get-EdgeDriver, Use-EdgeDriver, Stop-EdgeDriver,
New-FirefoxDriver, Get-FirefoxDriver, Use-FirefoxDriver, Stop-FirefoxDriver,
Exit-WebDriverLease, Complete-DumplingsWebDriverLease
