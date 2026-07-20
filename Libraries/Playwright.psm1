# SPDX-License-Identifier: Apache-2.0

# Source references:
# - Scrapling StealthyFetcher (BSD-3-Clause):
#   https://github.com/D4Vinci/Scrapling
# - Patchright driver (Apache-2.0):
#   https://github.com/Kaliiiiiiiiii-Vinyzu/patchright
# - Patchright .NET package (Apache-2.0):
#   https://github.com/DevEnterpriseSoftware/patchright-dotnet
# The PowerShell API is independently written. Scrapling provides behavioral
# guidance; Patchright is consumed as the pinned drop-in Playwright runtime.

# Patchright is a drop-in Playwright driver with Chromium anti-detection patches.
# It remains asynchronous internally, so Dumplings deliberately exposes a
# synchronous PowerShell boundary: task scripts run only as the outer scoped
# block, Task objects are completed by PlaywrightTaskBridge, and network routing
# is handled by PlaywrightSession's compiled C# delegate. Never pass a PowerShell
# scriptblock to RouteAsync, ExposeBindingAsync, or Playwright event callbacks;
# those callbacks can execute without the originating runspace and hang.

$Script:PlaywrightPoolStorageKey = '__DumplingsPlaywrightLeasePool'
$Script:PlaywrightLeaseDurationSeconds = 30
$Script:PlaywrightOperationTimeoutMilliseconds = 30000
$Script:StandalonePlaywrightPool = $null
$Script:PlaywrightRuntimePath = $null
$Script:PlaywrightLeases = [Collections.Concurrent.ConcurrentDictionary[string, object]]::new([StringComparer]::Ordinal)

# Keep request filtering in a data variable. The compiled session converts these
# wildcard values to Regex objects and invokes no PowerShell from route callbacks.
$Script:PlaywrightBlockedUrlPatterns = @(
  '*.bmp*', '*.gif*', '*.ico*', '*.jpeg*', '*.jpg*', '*.png*', '*.svg*', '*.webp*',
  '*.avi*', '*.m4a*', '*.m4v*', '*.mkv*', '*.mov*', '*.mp3*', '*.mp4*', '*.mpeg*', '*.ogg*', '*.wav*', '*.webm*',
  '*://youtube.com/*', '*://*.youtube.com/*', '*://youtu.be/*', '*://*.youtube-nocookie.com/*',
  '*://youtube.googleapis.com/*', '*://youtubei.googleapis.com/*', '*://*.ytimg.com/*', '*://*.googlevideo.com/*'
)

# This list follows Scrapling's disable_resources behavior where Playwright has
# an equivalent request resource type. URL/domain filters handle types such as
# beacon and object that are not exposed as stable Playwright resource values.
$Script:PlaywrightDisabledResourceTypes = @(
  'font', 'image', 'media', 'stylesheet', 'texttrack', 'websocket'
)
$Script:PlaywrightSessionParameterNames = @(
  'Browser', 'Channel', 'Headless', 'BlockUrlPattern', 'Stealth', 'DisableResources', 'BlockedDomain',
  'UserAgent', 'Locale', 'TimezoneId', 'ExtraHTTPHeaders', 'Proxy', 'ProxyCredential', 'ProxyBypass',
  'IgnoreHTTPSErrors', 'BlockWebRTC', 'DisableWebGL', 'DnsOverHttps', 'InitScriptPath', 'ExtraBrowserArgument'
)

function Select-PlaywrightSessionParameter {
  <#
  .SYNOPSIS
    Copy only session-level values from a public function's bound parameters.
  .PARAMETER BoundParameters
    PSBoundParameters from a Playwright facade.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$BoundParameters)

  $Result = @{}
  foreach ($Name in $Script:PlaywrightSessionParameterNames) {
    if ($BoundParameters.Keys -contains $Name) { $Result[$Name] = $BoundParameters[$Name] }
  }
  return $Result
}

function Import-PlaywrightTaskBridge {
  <#
  .SYNOPSIS
    Load the dependency-free C# Task completion bridge once per process.
  #>
  [CmdletBinding()]
  param ()

  if (([Management.Automation.PSTypeName]'Dumplings.Playwright.PlaywrightTaskBridge').Type) { return }
  $Mutex = [Threading.Mutex]::new($false, 'Local\Dumplings-PlaywrightTaskBridge')
  $Acquired = $false
  try {
    try { $Acquired = $Mutex.WaitOne([timespan]::FromMinutes(2)) } catch [Threading.AbandonedMutexException] { $Acquired = $true }
    if (-not $Acquired) { throw 'Timed out loading the Playwright Task bridge.' }
    if (-not ([Management.Automation.PSTypeName]'Dumplings.Playwright.PlaywrightTaskBridge').Type) {
      Add-Type -Path (Join-Path $PSScriptRoot '..' 'Assets' 'Source' 'Playwright' 'PlaywrightTaskBridge.cs')
    }
  } finally {
    if ($Acquired) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}

function Import-PlaywrightLeaseBroker {
  <#
  .SYNOPSIS
    Load the process-wide FIFO lease broker shared with browser automation.
  #>
  [CmdletBinding()]
  param ()

  if (([Management.Automation.PSTypeName]'Dumplings.WebDriver.WebDriverLeasePool').Type) { return }
  $Mutex = [Threading.Mutex]::new($false, 'Local\Dumplings-WebDriverLeaseBroker')
  $Acquired = $false
  try {
    try { $Acquired = $Mutex.WaitOne([timespan]::FromMinutes(2)) } catch [Threading.AbandonedMutexException] { $Acquired = $true }
    if (-not $Acquired) { throw 'Timed out loading the browser lease broker.' }
    if (-not ([Management.Automation.PSTypeName]'Dumplings.WebDriver.WebDriverLeasePool').Type) {
      Add-Type -Path (Join-Path $PSScriptRoot '..' 'Assets' 'Source' 'WebDriver' 'WebDriverLeasePool.cs')
    }
  } finally {
    if ($Acquired) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}

Import-PlaywrightTaskBridge
Import-PlaywrightLeaseBroker

function Get-PlaywrightLeaseOwnerId {
  <#
  .SYNOPSIS
    Return the runner-assigned owner or a standalone runspace owner.
  #>
  [OutputType([string])]
  param ()

  $Owner = Get-Variable -Name DumplingsPlaywrightLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  if ($Owner -and -not [string]::IsNullOrWhiteSpace([string]$Owner.Value)) { return [string]$Owner.Value }
  return "Standalone/$([Management.Automation.Runspaces.Runspace]::DefaultRunspace.InstanceId)"
}

function Get-PlaywrightLeaseDuration {
  <#
  .SYNOPSIS
    Resolve the contention-aware browser lease quantum.
  #>
  [OutputType([timespan])]
  param ()

  $Seconds = $Script:PlaywrightLeaseDurationSeconds
  $Preference = Get-Variable -Name DumplingsPreference -Scope Global -ErrorAction SilentlyContinue
  $Configured = 0
  if ($Preference -and $Preference.Value -is [Collections.IDictionary] -and
    $Preference.Value.Contains('PlaywrightLeaseDurationSeconds') -and
    [int]::TryParse([string]$Preference.Value.PlaywrightLeaseDurationSeconds, [ref]$Configured) -and $Configured -gt 0) {
    $Seconds = $Configured
  }
  return [timespan]::FromSeconds($Seconds)
}

function Get-PlaywrightOperationTimeout {
  <#
  .SYNOPSIS
    Resolve the timeout used for Playwright launch, navigation, and Task completion.
  #>
  [OutputType([int])]
  param ()

  $Milliseconds = $Script:PlaywrightOperationTimeoutMilliseconds
  $Preference = Get-Variable -Name DumplingsPreference -Scope Global -ErrorAction SilentlyContinue
  $Configured = 0
  if ($Preference -and $Preference.Value -is [Collections.IDictionary] -and
    $Preference.Value.Contains('PlaywrightOperationTimeoutMilliseconds') -and
    [int]::TryParse([string]$Preference.Value.PlaywrightOperationTimeoutMilliseconds, [ref]$Configured) -and $Configured -gt 0) {
    $Milliseconds = $Configured
  }
  return $Milliseconds
}

function Get-PlaywrightQueueTimeout {
  <#
  .SYNOPSIS
    Bound queue waiting by the runner timeout when one is configured.
  #>
  [OutputType([timespan])]
  param ()

  $Preference = Get-Variable -Name DumplingsPreference -Scope Global -ErrorAction SilentlyContinue
  $Seconds = 0
  if ($Preference -and $Preference.Value -is [Collections.IDictionary] -and
    $Preference.Value.Contains('Timeout') -and [int]::TryParse([string]$Preference.Value.Timeout, [ref]$Seconds) -and $Seconds -gt 0) {
    return [timespan]::FromSeconds($Seconds)
  }
  return [Threading.Timeout]::InfiniteTimeSpan
}

function Get-PlaywrightLeasePool {
  <#
  .SYNOPSIS
    Return the synchronized runner pool or the module-local standalone pool.
  .PARAMETER ExistingOnly
    Return null instead of creating a pool.
  #>
  [OutputType([Dumplings.WebDriver.WebDriverLeasePool])]
  param ([switch]$ExistingOnly)

  $Storage = Get-Variable -Name DumplingsStorage -Scope Global -ErrorAction SilentlyContinue
  if ($Storage -and $Storage.Value -is [hashtable] -and $Storage.Value.IsSynchronized) {
    [Threading.Monitor]::Enter($Storage.Value.SyncRoot)
    try {
      if (-not $Storage.Value.ContainsKey($Script:PlaywrightPoolStorageKey)) {
        if ($ExistingOnly) { return $null }
        $Storage.Value[$Script:PlaywrightPoolStorageKey] = [Dumplings.WebDriver.WebDriverLeasePool]::new()
      }
      return $Storage.Value[$Script:PlaywrightPoolStorageKey]
    } finally {
      [Threading.Monitor]::Exit($Storage.Value.SyncRoot)
    }
  }

  if (-not $Script:StandalonePlaywrightPool -and -not $ExistingOnly) {
    $Script:StandalonePlaywrightPool = [Dumplings.WebDriver.WebDriverLeasePool]::new()
  }
  return $Script:StandalonePlaywrightPool
}

function Import-PlaywrightRuntime {
  <#
  .SYNOPSIS
    Restore and load the pinned Playwright assembly and compiled session wrapper.
  .OUTPUTS
    The version-specific runtime directory.
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param ()

  if ($Script:PlaywrightRuntimePath -and ([Management.Automation.PSTypeName]'Dumplings.Playwright.PlaywrightSession').Type) {
    return $Script:PlaywrightRuntimePath
  }

  $PackageModuleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $RuntimeUtility = Import-Module (Join-Path $PackageModuleRoot 'Utilities' 'PlaywrightRuntime.psm1') -Force -PassThru
  $RuntimePath = & $RuntimeUtility {
    param ($LockPath)
    Initialize-DumplingsPlaywrightRuntime -LockPath $LockPath
  } (Join-Path $PackageModuleRoot 'Assets' 'PlaywrightRuntime.psd1')
  $AssemblyPath = Join-Path $RuntimePath 'Microsoft.Playwright.dll'
  $env:PLAYWRIGHT_DRIVER_SEARCH_PATH = $RuntimePath

  $LoadedAssembly = [AppDomain]::CurrentDomain.GetAssemblies().Where({ $_.GetName().Name -eq 'Microsoft.Playwright' }, 'First')
  if ($LoadedAssembly) {
    if ([IO.Path]::GetFullPath($LoadedAssembly.Location) -cne [IO.Path]::GetFullPath($AssemblyPath)) {
      throw "Microsoft.Playwright is already loaded from '$($LoadedAssembly.Location)', not the pinned runtime '${AssemblyPath}'"
    }
  } else {
    $LoadedAssembly = [Reflection.Assembly]::LoadFrom($AssemblyPath)
  }

  if (-not ([Management.Automation.PSTypeName]'Dumplings.Playwright.PlaywrightSession').Type) {
    $Mutex = [Threading.Mutex]::new($false, 'Local\Dumplings-PlaywrightSession')
    $Acquired = $false
    try {
      try { $Acquired = $Mutex.WaitOne([timespan]::FromMinutes(2)) } catch [Threading.AbandonedMutexException] { $Acquired = $true }
      if (-not $Acquired) { throw 'Timed out compiling the Playwright session wrapper.' }
      if (-not ([Management.Automation.PSTypeName]'Dumplings.Playwright.PlaywrightSession').Type) {
        # Supplying ReferencedAssemblies replaces Add-Type's default references.
        # Use PowerShell's matching reference set plus its async-interfaces
        # runtime so the wrapper compiles consistently on supported PS 7.4+ hosts.
        $References = [string[]]@(
          Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' -File | Select-Object -ExpandProperty FullName
        ) + @((Join-Path $PSHOME 'Microsoft.Bcl.AsyncInterfaces.dll'), $AssemblyPath)
        Add-Type -Path (Join-Path $PSScriptRoot '..' 'Assets' 'Source' 'Playwright' 'PlaywrightSession.cs') `
          -ReferencedAssemblies $References -ErrorAction Stop
      }
    } finally {
      if ($Acquired) { $Mutex.ReleaseMutex() }
      $Mutex.Dispose()
    }
  }

  $Script:PlaywrightRuntimePath = $RuntimePath
  return $RuntimePath
}

function Wait-PlaywrightTask {
  <#
  .SYNOPSIS
    Complete a Playwright Task synchronously and return its result.
  .DESCRIPTION
    Use this helper for Playwright methods that return Task or Task[T]. Do not
    register PowerShell scriptblocks as Playwright asynchronous callbacks.
  .PARAMETER Task
    Playwright Task returned by an asynchronous API.
  .PARAMETER TimeoutMilliseconds
    Completion timeout. Defaults to PlaywrightOperationTimeoutMilliseconds.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [Threading.Tasks.Task]$Task,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$TimeoutMilliseconds = (Get-PlaywrightOperationTimeout)
  )

  process {
    $Result = [Dumplings.Playwright.PlaywrightTaskBridge]::Wait($Task, [timespan]::FromMilliseconds($TimeoutMilliseconds))
    if ($null -ne $Result) { $Result }
  }
}

function Install-PlaywrightBrowser {
  <#
  .SYNOPSIS
    Install Patchright's version-coupled Chromium browser.
  .DESCRIPTION
    Dumplings uses the installed Microsoft Edge channel by default and does not
    need a browser download. Stealth mode defaults to installed Google Chrome.
    Call this explicitly only when using the bundled Chromium channel.
  .PARAMETER Browser
    Patchright browser payload. Only Chromium is supported by Patchright.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [ValidateSet('Chromium')]
    [string]$Browser
  )

  $null = Import-PlaywrightRuntime
  $ExitCode = [Microsoft.Playwright.Program]::Main([string[]]@('install', $Browser.ToLowerInvariant()))
  if ($ExitCode -ne 0) { throw "Playwright failed to install ${Browser} with exit code ${ExitCode}." }
}

function Get-PlaywrightDriverProcessSnapshot {
  <#
  .SYNOPSIS
    Find Playwright Node driver processes directly owned by this PowerShell host.
  .DESCRIPTION
    The lease broker uses the selected process ID to verify and terminate the
    complete browser process tree if graceful asynchronous disposal stalls.
  #>
  [OutputType([int[]])]
  param ()

  try {
    return [int[]]@(
      Get-CimInstance -ClassName Win32_Process -Filter "Name = 'node.exe' AND ParentProcessId = ${PID}" -ErrorAction Stop |
        Where-Object CommandLine -Match '(?i)\.playwright[\\/]package[\\/]cli\.js.*run-driver' |
        Select-Object -ExpandProperty ProcessId
    )
  } catch {
    return [int[]]@()
  }
}

function New-PooledPlaywrightResource {
  <#
  .SYNOPSIS
    Create the Playwright driver/browser resource retained by the lease pool.
  .PARAMETER Configuration
    Stable browser/channel/headless/filter identity used for safe reuse.
  .PARAMETER SessionConfiguration
    Fully validated settings consumed by the compiled Patchright session.
  #>
  [OutputType([Dumplings.WebDriver.WebDriverResource])]
  param (
    [Parameter(Mandatory)][string]$Configuration,
    [Parameter(Mandatory)][Dumplings.Playwright.PlaywrightSessionConfiguration]$SessionConfiguration
  )

  $null = Import-PlaywrightRuntime
  [int[]]$ExistingDriverProcesses = @(Get-PlaywrightDriverProcessSnapshot)
  $Session = $null
  try {
    $Session = [Dumplings.Playwright.PlaywrightSession]::Create($SessionConfiguration)
    # The Node driver is the verified root of the launched browser tree. Supplying
    # it to the existing broker gives preemption a bounded force-cleanup path.
    $DriverProcessId = @(Get-PlaywrightDriverProcessSnapshot | Where-Object { $_ -notin $ExistingDriverProcesses }) |
      Select-Object -First 1
    return [Dumplings.WebDriver.WebDriverResource]::new($Session, $null, [int]$DriverProcessId, $Configuration, [string[]]@())
  } catch {
    if ($Session) { $Session.Dispose() }
    throw
  }
}

function Get-PlaywrightLease {
  <#
  .SYNOPSIS
    Acquire the sole process-wide Playwright session for the current task.
  .PARAMETER Browser
    Playwright browser engine.
  .PARAMETER Channel
    Chromium distribution channel. Chromium defaults to installed Microsoft Edge.
  .PARAMETER Headless
    Launch without a visible browser window.
  .PARAMETER BlockUrlPattern
    URL wildcards blocked by a compiled C# route handler.
  .PARAMETER Stealth
    Use Patchright's Chromium anti-detection driver profile. Chrome is the
    default channel for this mode unless Channel is supplied explicitly.
  .PARAMETER DisableResources
    Block fonts, images, media, stylesheets, text tracks, and WebSockets.
  .PARAMETER BlockedDomain
    Block a domain and all of its subdomains in the compiled route callback.
  .PARAMETER UserAgent
    Explicit context user agent. Omit it to preserve Patchright's coherent fingerprint.
  .PARAMETER Locale
    Browser locale and Accept-Language locale.
  .PARAMETER TimezoneId
    ICU timezone identifier exposed by the browser context.
  .PARAMETER ExtraHTTPHeaders
    Additional context-wide HTTP headers.
  .PARAMETER Proxy
    HTTP, HTTPS, or SOCKS proxy URI.
  .PARAMETER ProxyCredential
    Optional credential for Proxy.
  .PARAMETER ProxyBypass
    Comma-separated domains that bypass Proxy.
  .PARAMETER IgnoreHTTPSErrors
    Continue through untrusted server certificates. Stealth mode enables this.
  .PARAMETER BlockWebRTC
    Restrict Chromium WebRTC to proxied traffic to avoid local-IP disclosure.
  .PARAMETER DisableWebGL
    Disable WebGL. This can itself be fingerprintable and is not the default.
  .PARAMETER DnsOverHttps
    Ask Chromium to resolve DNS through Cloudflare DNS-over-HTTPS.
  .PARAMETER InitScriptPath
    JavaScript file registered before any page script executes.
  .PARAMETER ExtraBrowserArgument
    Additional Chromium launch arguments. These can break browser behavior.
  #>
  [OutputType([Dumplings.WebDriver.WebDriverLease])]
  param (
    [ValidateSet('Chromium')][string]$Browser = 'Chromium',
    [AllowEmptyString()][string]$Channel,
    [switch]$Headless,
    [string[]]$BlockUrlPattern = $Script:PlaywrightBlockedUrlPatterns,
    [switch]$Stealth,
    [switch]$DisableResources,
    [string[]]$BlockedDomain,
    [AllowEmptyString()][string]$UserAgent,
    [AllowEmptyString()][string]$Locale,
    [AllowEmptyString()][string]$TimezoneId,
    [Collections.IDictionary]$ExtraHTTPHeaders,
    [uri]$Proxy,
    [pscredential]$ProxyCredential,
    [AllowEmptyString()][string]$ProxyBypass,
    [switch]$IgnoreHTTPSErrors,
    [switch]$BlockWebRTC,
    [switch]$DisableWebGL,
    [switch]$DnsOverHttps,
    [string]$InitScriptPath,
    [string[]]$ExtraBrowserArgument
  )

  if ($Browser -ne 'Chromium') {
    throw 'The pinned Patchright runtime supports only the Chromium browser engine.'
  }
  if ($Proxy -and $Proxy.Scheme -notin 'http', 'https', 'socks4', 'socks5') {
    throw "The Playwright proxy scheme '$($Proxy.Scheme)' is not supported."
  }
  if ($Proxy -and -not [string]::IsNullOrWhiteSpace($Proxy.UserInfo)) {
    throw 'Put proxy credentials in ProxyCredential rather than embedding them in Proxy.'
  }
  if (-not $PSBoundParameters.ContainsKey('Channel')) {
    $Channel = $Stealth ? 'chrome' : 'msedge'
  }
  if ($InitScriptPath) {
    $InitScriptPath = [IO.Path]::GetFullPath($InitScriptPath)
    if (-not (Test-Path -LiteralPath $InitScriptPath -PathType Leaf)) {
      throw "The Playwright initialization script does not exist: ${InitScriptPath}"
    }
  }
  $InitScriptHash = $InitScriptPath ? (Get-FileHash -LiteralPath $InitScriptPath -Algorithm SHA256).Hash : ''

  $NormalizedPatterns = [string[]]@($BlockUrlPattern | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
  $NormalizedDomains = [string[]]@($BlockedDomain | ForEach-Object { ([string]$_).Trim().Trim('.').ToLowerInvariant() } |
      Where-Object { $_ } | Sort-Object -Unique)
  $BlockedResourceTypes = $DisableResources ? [string[]]$Script:PlaywrightDisabledResourceTypes : [string[]]@()
  $Headers = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  if ($ExtraHTTPHeaders) {
    foreach ($Header in $ExtraHTTPHeaders.GetEnumerator()) {
      if ([string]::IsNullOrWhiteSpace([string]$Header.Key)) { throw 'Playwright HTTP header names cannot be empty.' }
      $Headers[[string]$Header.Key] = [string]$Header.Value
    }
  }

  $ProxyServer = $Proxy ? $Proxy.AbsoluteUri : ''
  $ProxyUsername = ''
  $ProxyPassword = ''
  if ($ProxyCredential) {
    if (-not $Proxy) { throw 'ProxyCredential requires Proxy.' }
    $NetworkCredential = $ProxyCredential.GetNetworkCredential()
    $ProxyUsername = $NetworkCredential.UserName
    $ProxyPassword = $NetworkCredential.Password
  }

  $null = Import-PlaywrightRuntime
  $SessionConfiguration = [Dumplings.Playwright.PlaywrightSessionConfiguration]::new()
  $SessionConfiguration.BrowserName = $Browser
  $SessionConfiguration.Channel = $Channel
  $SessionConfiguration.Headless = $Headless.IsPresent
  $SessionConfiguration.OperationTimeoutMilliseconds = Get-PlaywrightOperationTimeout
  $SessionConfiguration.Stealth = $Stealth.IsPresent
  $SessionConfiguration.IgnoreHttpsErrors = $IgnoreHTTPSErrors.IsPresent
  $SessionConfiguration.BlockWebRtc = $BlockWebRTC.IsPresent
  $SessionConfiguration.DisableWebGl = $DisableWebGL.IsPresent
  $SessionConfiguration.DnsOverHttps = $DnsOverHttps.IsPresent
  $SessionConfiguration.UserAgent = $UserAgent ?? ''
  $SessionConfiguration.Locale = $Locale ?? ''
  $SessionConfiguration.TimezoneId = $TimezoneId ?? ''
  $SessionConfiguration.ProxyServer = $ProxyServer
  $SessionConfiguration.ProxyUsername = $ProxyUsername
  $SessionConfiguration.ProxyPassword = $ProxyPassword
  $SessionConfiguration.ProxyBypass = $ProxyBypass ?? ''
  $SessionConfiguration.InitScriptPath = $InitScriptPath ?? ''
  $SessionConfiguration.ExtraBrowserArguments = [string[]]@($ExtraBrowserArgument)
  $SessionConfiguration.BlockedUrlPatterns = $NormalizedPatterns
  $SessionConfiguration.BlockedResourceTypes = $BlockedResourceTypes
  $SessionConfiguration.BlockedDomains = $NormalizedDomains
  $SessionConfiguration.ExtraHttpHeaders = $Headers

  # Hash every launch/context setting, including secrets, so incompatible leases
  # never share a context while no credential appears in diagnostics.
  $ConfigurationMaterial = @(
    $Browser, $Channel, $Headless.IsPresent, $Stealth.IsPresent, $DisableResources.IsPresent,
    $UserAgent, $Locale, $TimezoneId, $ProxyServer, $ProxyUsername, $ProxyPassword, $ProxyBypass,
    $IgnoreHTTPSErrors.IsPresent, $BlockWebRTC.IsPresent, $DisableWebGL.IsPresent, $DnsOverHttps.IsPresent,
    $InitScriptPath, $InitScriptHash, ($NormalizedPatterns -join "`n"), ($NormalizedDomains -join "`n"),
    ($ExtraBrowserArgument -join "`n"), (($Headers.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key):$($_.Value)" }) -join "`n")
  ) -join "`0"
  $ConfigurationHash = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($ConfigurationMaterial))
  ).Substring(0, 16)
  $Configuration = "Patchright:${Browser}:${Channel}:$(if ($Headless) { 'Headless' } else { 'Visible' }):${ConfigurationHash}"
  $ResourceFactory = ${function:New-PooledPlaywrightResource}
  $Factory = [Func[Dumplings.WebDriver.WebDriverResource]] {
    & $ResourceFactory -Configuration $Configuration -SessionConfiguration $SessionConfiguration
  }.GetNewClosure()
  $OwnerId = Get-PlaywrightLeaseOwnerId
  $Pool = Get-PlaywrightLeasePool
  $Lease = $Pool.Acquire($OwnerId, $Configuration, $Factory, (Get-PlaywrightLeaseDuration), (Get-PlaywrightQueueTimeout))
  $Script:PlaywrightLeases[$OwnerId] = $Lease
  return $Lease
}

function Get-PlaywrightSession {
  <#
  .SYNOPSIS
    Acquire and return the managed Playwright session.
  .PARAMETER Browser
    Playwright browser engine.
  .PARAMETER Channel
    Chromium distribution channel.
  .PARAMETER Headless
    Launch without a visible browser window.
  .PARAMETER BlockUrlPattern
    URL wildcards blocked in the isolated context.
  .PARAMETER Stealth
    Enable the Patchright stealth profile.
  .PARAMETER DisableResources
    Block nonessential resource types.
  .PARAMETER BlockedDomain
    Domains and subdomains blocked by the compiled route handler.
  .PARAMETER UserAgent
    Explicit user agent override.
  .PARAMETER Locale
    Browser locale.
  .PARAMETER TimezoneId
    ICU timezone identifier.
  .PARAMETER ExtraHTTPHeaders
    Context-wide HTTP headers.
  .PARAMETER Proxy
    Proxy URI.
  .PARAMETER ProxyCredential
    Optional proxy credential.
  .PARAMETER ProxyBypass
    Comma-separated proxy bypass list.
  .PARAMETER IgnoreHTTPSErrors
    Ignore server certificate failures.
  .PARAMETER BlockWebRTC
    Prevent non-proxied Chromium WebRTC traffic.
  .PARAMETER DisableWebGL
    Disable Chromium WebGL.
  .PARAMETER DnsOverHttps
    Use Cloudflare DNS-over-HTTPS in Chromium.
  .PARAMETER InitScriptPath
    JavaScript file installed before page scripts.
  .PARAMETER ExtraBrowserArgument
    Extra Chromium launch arguments.
  #>
  param (
    [ValidateSet('Chromium')][string]$Browser = 'Chromium',
    [AllowEmptyString()][string]$Channel,
    [switch]$Headless,
    [string[]]$BlockUrlPattern = $Script:PlaywrightBlockedUrlPatterns,
    [switch]$Stealth,
    [switch]$DisableResources,
    [string[]]$BlockedDomain,
    [AllowEmptyString()][string]$UserAgent,
    [AllowEmptyString()][string]$Locale,
    [AllowEmptyString()][string]$TimezoneId,
    [Collections.IDictionary]$ExtraHTTPHeaders,
    [uri]$Proxy,
    [pscredential]$ProxyCredential,
    [AllowEmptyString()][string]$ProxyBypass,
    [switch]$IgnoreHTTPSErrors,
    [switch]$BlockWebRTC,
    [switch]$DisableWebGL,
    [switch]$DnsOverHttps,
    [string]$InitScriptPath,
    [string[]]$ExtraBrowserArgument
  )

  $Parameters = Select-PlaywrightSessionParameter -BoundParameters $PSBoundParameters
  if (-not $Parameters.ContainsKey('Browser')) { $Parameters.Browser = $Browser }
  if (-not $Parameters.ContainsKey('BlockUrlPattern')) { $Parameters.BlockUrlPattern = $BlockUrlPattern }
  return (Get-PlaywrightLease @Parameters).Driver
}

function Get-PlaywrightPage {
  <#
  .SYNOPSIS
    Acquire the managed session and return its current isolated page.
  #>
  param (
    [ValidateSet('Chromium')][string]$Browser = 'Chromium',
    [AllowEmptyString()][string]$Channel,
    [switch]$Headless,
    [string[]]$BlockUrlPattern = $Script:PlaywrightBlockedUrlPatterns,
    [switch]$Stealth,
    [switch]$DisableResources,
    [string[]]$BlockedDomain,
    [AllowEmptyString()][string]$UserAgent,
    [AllowEmptyString()][string]$Locale,
    [AllowEmptyString()][string]$TimezoneId,
    [Collections.IDictionary]$ExtraHTTPHeaders,
    [uri]$Proxy,
    [pscredential]$ProxyCredential,
    [AllowEmptyString()][string]$ProxyBypass,
    [switch]$IgnoreHTTPSErrors,
    [switch]$BlockWebRTC,
    [switch]$DisableWebGL,
    [switch]$DnsOverHttps,
    [string]$InitScriptPath,
    [string[]]$ExtraBrowserArgument
  )

  $Parameters = Select-PlaywrightSessionParameter -BoundParameters $PSBoundParameters
  if (-not $Parameters.ContainsKey('Browser')) { $Parameters.Browser = $Browser }
  if (-not $Parameters.ContainsKey('BlockUrlPattern')) { $Parameters.BlockUrlPattern = $BlockUrlPattern }
  return (Get-PlaywrightSession @Parameters).Page
}

function Reset-PlaywrightSession {
  <#
  .SYNOPSIS
    Replace task-specific context and page state before browser reuse.
  .PARAMETER Lease
    Active lease containing a Dumplings PlaywrightSession.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)]$Lease)

  try { return [bool]$Lease.Driver.Reset() } catch { return $false }
}

function ConvertTo-PlaywrightLeaseOutcome {
  <#
  .SYNOPSIS
    Relabel generic broker diagnostics for the Playwright-facing API.
  .PARAMETER Outcome
    Outcome record produced by the shared browser lease broker.
  #>
  param ($Outcome)

  if (-not $Outcome) { return }
  return [pscustomobject]@{
    OwnerId      = $Outcome.OwnerId
    Outcome      = $Outcome.Outcome
    Message      = ([string]$Outcome.Message).Replace('WebDriver', 'Playwright')
    TimestampUtc = $Outcome.TimestampUtc
  }
}

function Exit-PlaywrightLease {
  <#
  .SYNOPSIS
    Release or recycle the current task's Playwright lease.
  .PARAMETER OwnerId
    Runner task owner identity.
  .PARAMETER Failed
    Recycle because task or Playwright work failed.
  .PARAMETER Recycle
    Force-stop the retained browser instead of reusing it.
  #>
  param (
    [string]$OwnerId = (Get-PlaywrightLeaseOwnerId),
    [switch]$Failed,
    [switch]$Recycle
  )

  $Pool = Get-PlaywrightLeasePool -ExistingOnly
  if (-not $Pool) {
    $Removed = $null
    $null = $Script:PlaywrightLeases.TryRemove($OwnerId, [ref]$Removed)
    return
  }

  $Lease = $Pool.GetActiveLease($OwnerId)
  $ResetFailed = $false
  if ($Lease -and -not $Failed -and -not $Recycle) { $ResetFailed = -not (Reset-PlaywrightSession -Lease $Lease) }
  if ($Lease) {
    $ShouldRecycle = $Failed -or $Recycle -or $ResetFailed
    $Outcome = if ($Failed -or $ResetFailed) { [Dumplings.WebDriver.WebDriverLeaseOutcome]::Failed } elseif ($Recycle) {
      [Dumplings.WebDriver.WebDriverLeaseOutcome]::Stopped
    } else { [Dumplings.WebDriver.WebDriverLeaseOutcome]::Released }
    $Message = if ($ResetFailed) { 'The Playwright context reset failed and the browser was recycled.' } elseif ($Failed) {
      'The task failed while holding the Playwright lease.'
    } elseif ($Recycle) { 'The Playwright browser was stopped and recycled.' } else { 'The Playwright lease was released.' }
    $null = $Pool.Release($OwnerId, $Lease.Generation, $Outcome, $ShouldRecycle, $Message)
  }

  $Removed = $null
  $null = $Script:PlaywrightLeases.TryRemove($OwnerId, [ref]$Removed)
  $Result = ConvertTo-PlaywrightLeaseOutcome -Outcome ($Pool.GetOutcome($OwnerId))
  if ($ResetFailed) { throw 'The shared Playwright session could not be reset and was recycled.' }
  return $Result
}

function Save-PlaywrightScreenshot {
  <#
  .SYNOPSIS
    Save the current Playwright page to the Dumplings output directory.
  .PARAMETER Page
    Current Microsoft.Playwright.IPage instance.
  .PARAMETER OwnerId
    Runner task owner used in the output filename.
  .PARAMETER Failed
    Mark the screenshot as failure evidence.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]$Page,
    [Parameter(Mandatory)][string]$OwnerId,
    [switch]$Failed
  )

  $Output = Get-Variable -Name DumplingsOutput -Scope Global -ErrorAction SilentlyContinue
  $OutputDirectory = $Output -and $Output.Value ? [string]$Output.Value : (Join-Path (Get-Location).Path 'Outputs')
  $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
  $OwnerParts = @($OwnerId -split '/', 3)
  $TaskName = $OwnerParts.Count -gt 1 ? $OwnerParts[1] : $OwnerParts[0]
  $InvalidPattern = '[' + [regex]::Escape(( -join [IO.Path]::GetInvalidFileNameChars())) + ']'
  $SafeTaskName = ([regex]::Replace($TaskName, $InvalidPattern, '_')).Trim().TrimEnd('.')
  if ([string]::IsNullOrWhiteSpace($SafeTaskName)) { $SafeTaskName = 'Playwright' }
  if ($SafeTaskName.Length -gt 80) { $SafeTaskName = $SafeTaskName.Substring(0, 80) }
  $Status = $Failed ? 'Failed' : 'Succeeded'
  $Timestamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssfffffffZ', [Globalization.CultureInfo]::InvariantCulture)
  $Path = Join-Path $OutputDirectory "Playwright-${SafeTaskName}-${Status}-${Timestamp}.png"
  $Options = [Microsoft.Playwright.PageScreenshotOptions]::new()
  $Options.Path = $Path
  $Options.FullPage = $true
  $null = Wait-PlaywrightTask -Task ($Page.ScreenshotAsync($Options))
  return $Path
}

function Open-PlaywrightPage {
  <#
  .SYNOPSIS
    Navigate a leased Playwright page through the synchronous task boundary.
  .DESCRIPTION
    This helper centralizes the bounded GotoAsync call used by task scripts. It
    must be called inside Use-PlaywrightPage and returns the detached HTTP
    response metadata object owned by Playwright for the duration of the lease.
  .PARAMETER Page
    Active Microsoft.Playwright.IPage supplied by Use-PlaywrightPage.
  .PARAMETER Uri
    HTTP, HTTPS, data, or about URI to open.
  .PARAMETER WaitUntil
    Readiness state required before navigation completes.
  .PARAMETER Referer
    Optional navigation referer.
  #>
  param (
    [Parameter(Mandatory)]$Page,
    [Parameter(Mandatory)][uri]$Uri,
    [ValidateSet('Commit', 'DOMContentLoaded', 'Load', 'NetworkIdle')][string]$WaitUntil = 'DOMContentLoaded',
    [uri]$Referer
  )

  $Options = [Microsoft.Playwright.PageGotoOptions]::new()
  $Options.WaitUntil = [Microsoft.Playwright.WaitUntilState]$WaitUntil
  if ($Referer) { $Options.Referer = $Referer.AbsoluteUri }
  $Response = Wait-PlaywrightTask -Task ($Page.GotoAsync($Uri.AbsoluteUri, $Options))
  if (-not $Response -and $Uri.Scheme -in 'http', 'https') {
    throw "Playwright navigation returned no HTTP response for '$($Uri.AbsoluteUri)'."
  }
  return $Response
}

function Read-PlaywrightPageContent {
  <#
  .SYNOPSIS
    Return the current page HTML as detached text.
  .PARAMETER Page
    Active Microsoft.Playwright.IPage supplied by Use-PlaywrightPage.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)]$Page)

  return [string](Wait-PlaywrightTask -Task $Page.ContentAsync())
}

function Read-PlaywrightLocator {
  <#
  .SYNOPSIS
    Wait for one locator and return a detached scalar value.
  .DESCRIPTION
    Playwright locators auto-wait for most read operations. An explicit attached
    or visible wait is performed first so missing dynamic content fails with a
    bounded, actionable error rather than returning a live locator to the task.
  .PARAMETER Page
    Active Microsoft.Playwright.IPage supplied by Use-PlaywrightPage.
  .PARAMETER Selector
    Playwright selector. Prefix XPath expressions with xpath=.
  .PARAMETER Property
    Detached value to read from the first matching element.
  .PARAMETER AttributeName
    Attribute used when Property is Attribute.
  .PARAMETER State
    Locator state required before the value is read.
  .PARAMETER TimeoutMilliseconds
    Maximum wait for the locator and read operation.
  .PARAMETER Optional
    Return null when the selector does not reach the requested state. Use this
    for optional release-note entries whose absence is normal package evidence.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]$Page,
    [Parameter(Mandatory)][string]$Selector,
    [ValidateSet('InnerHTML', 'InnerText', 'TextContent', 'Attribute')][string]$Property = 'InnerHTML',
    [string]$AttributeName,
    [ValidateSet('Attached', 'Visible')][string]$State = 'Attached',
    [ValidateRange(1, [int]::MaxValue)][int]$TimeoutMilliseconds = (Get-PlaywrightOperationTimeout),
    [switch]$Optional
  )

  if ($Property -eq 'Attribute' -and [string]::IsNullOrWhiteSpace($AttributeName)) {
    throw 'AttributeName is required when reading a Playwright locator attribute.'
  }

  $Locator = $Page.Locator($Selector).First
  $WaitOptions = [Microsoft.Playwright.LocatorWaitForOptions]::new()
  $WaitOptions.State = [Microsoft.Playwright.WaitForSelectorState]$State
  $WaitOptions.Timeout = [float]$TimeoutMilliseconds
  try {
    $null = Wait-PlaywrightTask -Task ($Locator.WaitForAsync($WaitOptions)) -TimeoutMilliseconds $TimeoutMilliseconds
  } catch {
    if ($Optional) { return $null }
    throw
  }

  $Value = switch ($Property) {
    'InnerHTML' { Wait-PlaywrightTask -Task $Locator.InnerHTMLAsync() -TimeoutMilliseconds $TimeoutMilliseconds }
    'InnerText' { Wait-PlaywrightTask -Task $Locator.InnerTextAsync() -TimeoutMilliseconds $TimeoutMilliseconds }
    'TextContent' { Wait-PlaywrightTask -Task $Locator.TextContentAsync() -TimeoutMilliseconds $TimeoutMilliseconds }
    'Attribute' { Wait-PlaywrightTask -Task $Locator.GetAttributeAsync($AttributeName) -TimeoutMilliseconds $TimeoutMilliseconds }
  }
  if ($null -ne $Value) { return [string]$Value }
}

function Invoke-PlaywrightJavaScript {
  <#
  .SYNOPSIS
    Evaluate JavaScript and deserialize its JSON-safe result.
  .DESCRIPTION
    The supplied expression must be a JavaScript function. Its result is awaited,
    serialized in the page, and deserialized in PowerShell so no JavaScriptHandle
    or browser-owned object escapes the Playwright lease.
  .PARAMETER Page
    Active Microsoft.Playwright.IPage supplied by Use-PlaywrightPage.
  .PARAMETER Expression
    JavaScript function expression, for example () => window.appData.
  .PARAMETER Argument
    Optional JSON-serializable argument passed to the function.
  .PARAMETER TimeoutMilliseconds
    Maximum evaluation time.
  #>
  param (
    [Parameter(Mandatory)]$Page,
    [Parameter(Mandatory)][string]$Expression,
    $Argument,
    [ValidateRange(1, [int]::MaxValue)][int]$TimeoutMilliseconds = (Get-PlaywrightOperationTimeout)
  )

  $Wrapper = "async (argument) => JSON.stringify(await (${Expression})(argument))"
  $Json = Wait-PlaywrightTask -Task ($Page.EvaluateAsync[string]($Wrapper, $Argument)) -TimeoutMilliseconds $TimeoutMilliseconds
  if ([string]::IsNullOrEmpty($Json)) { return $null }
  return $Json | ConvertFrom-Json -AsHashtable -NoEnumerate
}

function Use-PlaywrightPage {
  <#
  .SYNOPSIS
    Run a synchronous PowerShell block with a leased Playwright page.
  .DESCRIPTION
    The script block receives Page, Context, Browser, and Session arguments. Use
    Wait-PlaywrightTask for asynchronous methods. The block itself is never
    registered as a Playwright callback and always releases the lease in finally.
  .PARAMETER Browser
    Playwright browser engine.
  .PARAMETER Channel
    Chromium distribution channel. Defaults to installed Microsoft Edge.
  .PARAMETER Headless
    Launch without a visible browser window.
  .PARAMETER BlockUrlPattern
    URL wildcards blocked by the compiled route handler. Pass an empty array to disable filtering.
  .PARAMETER Stealth
    Use Patchright's Chromium stealth profile and default to installed Chrome.
  .PARAMETER DisableResources
    Block nonessential fonts, images, media, stylesheets, text tracks, and WebSockets.
  .PARAMETER BlockedDomain
    Block each domain and all of its subdomains.
  .PARAMETER UserAgent
    Explicit user agent override. Omit for the most coherent Patchright fingerprint.
  .PARAMETER Locale
    Browser locale and Accept-Language locale.
  .PARAMETER TimezoneId
    ICU timezone identifier.
  .PARAMETER ExtraHTTPHeaders
    Context-wide HTTP headers.
  .PARAMETER Proxy
    HTTP, HTTPS, or SOCKS proxy URI.
  .PARAMETER ProxyCredential
    Optional credential for Proxy.
  .PARAMETER ProxyBypass
    Comma-separated proxy bypass list.
  .PARAMETER IgnoreHTTPSErrors
    Continue through untrusted server certificates.
  .PARAMETER BlockWebRTC
    Prevent Chromium WebRTC from bypassing a proxy.
  .PARAMETER DisableWebGL
    Disable WebGL; use only when site behavior requires it.
  .PARAMETER DnsOverHttps
    Route Chromium DNS through Cloudflare DNS-over-HTTPS.
  .PARAMETER InitScriptPath
    JavaScript file registered before page scripts execute.
  .PARAMETER ExtraBrowserArgument
    Additional Chromium launch arguments.
  .PARAMETER Screenshot
    Capture the final page after success or failure.
  .PARAMETER ScriptBlock
    Synchronous task code receiving Page, Context, Browser, and Session.
  #>
  param (
    [ValidateSet('Chromium')][string]$Browser = 'Chromium',
    [AllowEmptyString()][string]$Channel,
    [switch]$Headless,
    [string[]]$BlockUrlPattern = $Script:PlaywrightBlockedUrlPatterns,
    [switch]$Stealth,
    [switch]$DisableResources,
    [string[]]$BlockedDomain,
    [AllowEmptyString()][string]$UserAgent,
    [AllowEmptyString()][string]$Locale,
    [AllowEmptyString()][string]$TimezoneId,
    [Collections.IDictionary]$ExtraHTTPHeaders,
    [uri]$Proxy,
    [pscredential]$ProxyCredential,
    [AllowEmptyString()][string]$ProxyBypass,
    [switch]$IgnoreHTTPSErrors,
    [switch]$BlockWebRTC,
    [switch]$DisableWebGL,
    [switch]$DnsOverHttps,
    [string]$InitScriptPath,
    [string[]]$ExtraBrowserArgument,
    [switch]$Screenshot,
    [Parameter(Mandatory, Position = 0)][scriptblock]$ScriptBlock
  )

  $OwnerId = Get-PlaywrightLeaseOwnerId
  $Succeeded = $false
  $Session = $null
  try {
    $Parameters = Select-PlaywrightSessionParameter -BoundParameters $PSBoundParameters
    if (-not $Parameters.ContainsKey('Browser')) { $Parameters.Browser = $Browser }
    if (-not $Parameters.ContainsKey('BlockUrlPattern')) { $Parameters.BlockUrlPattern = $BlockUrlPattern }
    $Session = Get-PlaywrightSession @Parameters
    # Capture callback output before publishing it to the caller. Without this
    # boundary, a downstream pipeline failure (for example ConvertFrom-Html)
    # can stop output enumeration before Succeeded is set and incorrectly mark
    # a healthy browser lease as failed.
    $Result = & $ScriptBlock $Session.Page $Session.Context $Session.Browser $Session
    $Succeeded = $true
    $Result
  } finally {
    try {
      if ($Screenshot -and $Session -and $Session.Page) {
        try {
          $Path = Save-PlaywrightScreenshot -Page $Session.Page -OwnerId $OwnerId -Failed:(-not $Succeeded)
          Write-Verbose -Message "The Playwright screenshot was saved to: ${Path}"
        } catch {
          Write-Warning -Message "Failed to save the Playwright screenshot: $($_.Exception.Message)" -WarningAction Continue
        }
      }
    } finally {
      $null = Exit-PlaywrightLease -OwnerId $OwnerId -Failed:(-not $Succeeded)
    }
  }
}

function Get-PlaywrightCloudflareChallengeType {
  <#
  .SYNOPSIS
    Identify Cloudflare challenge evidence in detached page HTML.
  .PARAMETER Content
    Complete page HTML returned by Playwright.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

  foreach ($Type in 'non-interactive', 'managed', 'interactive') {
    if ($Content.Contains("cType: '${Type}'", [StringComparison]::Ordinal)) { return $Type }
  }
  if ($Content -match '(?i)challenges\.cloudflare\.com/turnstile/' -or $Content -match '(?i)class=["''][^"'']*cf-turnstile') {
    return 'embedded'
  }
  if ($Content -match '(?is)<title>\s*Just a moment(?:\.\.\.)?\s*</title>' -or
    $Content -match '(?i)Verifying you are human') {
    return 'managed'
  }
  return $null
}

function Get-PlaywrightCloudflareFrameClickPoint {
  <#
  .SYNOPSIS
    Derive the frame-relative checkbox click point from a Cloudflare challenge rectangle.
  .DESCRIPTION
    Interactive Turnstile frames can render their checkbox without a locator-
    visible input. The checkbox occupies the left side of the verified frame,
    so this helper calculates one bounded point without relying on randomized
    element IDs or inspecting challenge implementation details.
  .PARAMETER BoundingBox
    Playwright frame-element rectangle with X, Y, Width, and Height values.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$BoundingBox)

  $Width = [double]$BoundingBox.Width
  $Height = [double]$BoundingBox.Height
  if ($Width -le 0 -or $Height -le 0) { return $null }

  # Stay inside small or resized widgets while targeting the checkbox area used
  # by the normal 300-by-65 Turnstile interaction frame.
  return [pscustomobject]@{
    X = [Math]::Max(1.0, [Math]::Min(28.0, $Width / 4.0))
    Y = $Height / 2.0
  }
}

function Invoke-PlaywrightCloudflareChallenge {
  <#
  .SYNOPSIS
    Best-effort wait/click handling for a Cloudflare challenge in Patchright.
  .DESCRIPTION
    Patchright supplies the anti-detection behavior. This routine only detects
    challenge state and performs the same ordinary page interaction a user would.
    It has a strict deadline and does not use an external CAPTCHA service.
  .PARAMETER Page
    Active Patchright Playwright page.
  .PARAMETER TimeoutMilliseconds
    Maximum total time allowed for challenge handling.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]$Page,
    [ValidateRange(1000, [int]::MaxValue)][int]$TimeoutMilliseconds = 60000
  )

  $Deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
  # Turnstile attaches its iframe before the interactive control is painted.
  # Defer the coordinate-only fallback so its one click is not consumed early.
  $NextChallengeClickAt = [DateTime]::UtcNow.AddSeconds(5)
  $InitialType = $null
  $ChallengeClickCount = 0
  while ([DateTime]::UtcNow -lt $Deadline) {
    try {
      $Content = [string](Wait-PlaywrightTask -Task $Page.ContentAsync() -TimeoutMilliseconds $TimeoutMilliseconds)
    } catch {
      if ($Page.IsClosed) { throw }
      # A completed challenge replaces the 403 document. ContentAsync can race
      # that navigation; retry polling instead of treating success as failure.
      $Remaining = [Math]::Max(1, [int]($Deadline - [DateTime]::UtcNow).TotalMilliseconds)
      $null = Wait-PlaywrightTask -Task ($Page.WaitForTimeoutAsync([Math]::Min(250, $Remaining))) -TimeoutMilliseconds ([Math]::Min(750, $Remaining + 500))
      continue
    }
    $ChallengeType = Get-PlaywrightCloudflareChallengeType -Content $Content
    if (-not $InitialType) { $InitialType = $ChallengeType }
    if (-not $ChallengeType) { return $InitialType }

    if ($ChallengeClickCount -lt 3 -and $ChallengeType -ne 'non-interactive' -and
      ($ChallengeClickCount -eq 0 -or [DateTime]::UtcNow -ge $NextChallengeClickAt)) {
      $ClickedThisPass = $false
      # Patchright exposes closed shadow roots to normal locators. Try stable
      # Turnstile selectors once, then let the challenge's own state advance.
      $ChallengeFrames = @($Page.Frames | Where-Object { $_.Url -match '^https?://challenges\.cloudflare\.com/' })
      $Candidates = @(
        'input[type="checkbox"]',
        '#cf_turnstile input',
        '#cf-turnstile input',
        '.main-content input[type="checkbox"]'
      )
      foreach ($Frame in $ChallengeFrames + @($Page.MainFrame)) {
        foreach ($Selector in $Candidates) {
          try {
            $Locator = $Frame.Locator($Selector).First
            if (Wait-PlaywrightTask -Task $Locator.IsVisibleAsync() -TimeoutMilliseconds 2000) {
              $null = Wait-PlaywrightTask -Task $Locator.ClickAsync() -TimeoutMilliseconds 5000
              Write-Verbose -Message "Clicked Cloudflare challenge locator '${Selector}'."
              $ClickedThisPass = $true
              $ChallengeClickCount++
              $NextChallengeClickAt = [DateTime]::UtcNow.AddSeconds(5)
              break
            }
          } catch {
            Write-Verbose -Message "Cloudflare challenge locator '${Selector}' was unavailable: $($_.Exception.Message)"
          }
        }
        if ($ClickedThisPass) { break }
      }

      if (-not $ClickedThisPass -and [DateTime]::UtcNow -ge $NextChallengeClickAt) {
        # Current interactive challenge frames paint the checkbox without an
        # input node. Restrict the coordinate fallback to Cloudflare-owned
        # frames and click the bounded left-side control just as a user would.
        foreach ($Frame in $ChallengeFrames) {
          try {
            $FrameElement = Wait-PlaywrightTask -Task $Frame.FrameElementAsync() -TimeoutMilliseconds 2000
            $BoundingBox = Wait-PlaywrightTask -Task $FrameElement.BoundingBoxAsync() -TimeoutMilliseconds 2000
            if ($Point = Get-PlaywrightCloudflareFrameClickPoint -BoundingBox $BoundingBox) {
              # Click relative to the iframe itself. A page-level coordinate can
              # miss when Cloudflare recenters the widget after layout settles.
              $ClickOptions = [Microsoft.Playwright.ElementHandleClickOptions]::new()
              $ClickOptions.Position = [Microsoft.Playwright.Position]::new()
              $ClickOptions.Position.X = $Point.X
              $ClickOptions.Position.Y = $Point.Y
              $null = Wait-PlaywrightTask -Task ($FrameElement.ClickAsync($ClickOptions)) -TimeoutMilliseconds 5000
              Write-Verbose -Message "Clicked Cloudflare challenge frame at relative point $($Point.X),$($Point.Y)."
              $ClickedThisPass = $true
              $ChallengeClickCount++
              $NextChallengeClickAt = [DateTime]::UtcNow.AddSeconds(5)
              break
            }
          } catch {
            Write-Verbose -Message "Cloudflare challenge frame interaction failed: $($_.Exception.Message)"
          }
        }
      }
    }

    $Remaining = [Math]::Max(1, [int]($Deadline - [DateTime]::UtcNow).TotalMilliseconds)
    $null = Wait-PlaywrightTask -Task ($Page.WaitForTimeoutAsync([Math]::Min(500, $Remaining))) -TimeoutMilliseconds ([Math]::Min(1000, $Remaining + 500))
  }
  throw "The Cloudflare challenge did not complete within ${TimeoutMilliseconds} ms."
}

function Invoke-PlaywrightFetch {
  <#
  .SYNOPSIS
    Fetch a page through a scoped Patchright session and return detached evidence.
  .DESCRIPTION
    This is the Dumplings equivalent of Scrapling's StealthyFetcher navigation
    workflow. It supports bounded retries, navigation/load waits, selector waits,
    a Google referer, and optional Cloudflare handling. Returned data contains no
    live Playwright objects and remains safe after the browser lease is released.
  .PARAMETER Uri
    HTTP or HTTPS page to navigate to with a GET request.
  .PARAMETER Browser
    Browser engine. The pinned Patchright runtime supports Chromium.
  .PARAMETER Channel
    Chromium channel. Stealth defaults to chrome; ordinary mode defaults to msedge.
  .PARAMETER Headless
    Launch without a visible browser window.
  .PARAMETER BlockUrlPattern
    URL wildcard filters evaluated by compiled C#.
  .PARAMETER Stealth
    Enable Patchright context hardening and stealth defaults.
  .PARAMETER DisableResources
    Block nonessential resource types.
  .PARAMETER BlockedDomain
    Block domains and their subdomains.
  .PARAMETER UserAgent
    Explicit user agent; omit to retain Patchright's native fingerprint.
  .PARAMETER Locale
    Browser locale.
  .PARAMETER TimezoneId
    ICU timezone identifier.
  .PARAMETER ExtraHTTPHeaders
    Context-wide request headers.
  .PARAMETER Proxy
    HTTP, HTTPS, or SOCKS proxy URI.
  .PARAMETER ProxyCredential
    Optional proxy credential.
  .PARAMETER ProxyBypass
    Comma-separated proxy bypass list.
  .PARAMETER IgnoreHTTPSErrors
    Ignore server certificate errors.
  .PARAMETER BlockWebRTC
    Prevent Chromium WebRTC from bypassing the proxy.
  .PARAMETER DisableWebGL
    Disable Chromium WebGL.
  .PARAMETER DnsOverHttps
    Use Cloudflare DNS-over-HTTPS.
  .PARAMETER InitScriptPath
    JavaScript file installed before page scripts.
  .PARAMETER ExtraBrowserArgument
    Extra Chromium launch arguments.
  .PARAMETER Cookie
    Cookie dictionaries applied before navigation. Name and Value plus either Url
    or Domain and Path follow Microsoft.Playwright.Cookie fields.
  .PARAMETER PageSetup
    Synchronous PowerShell setup invoked before navigation. Do not register it as
    a Playwright event or route callback.
  .PARAMETER PageAction
    Synchronous PowerShell action invoked after navigation and challenge handling.
  .PARAMETER CaptureXhr
    Regular expression selecting XHR/fetch response URLs to capture as detached evidence.
  .PARAMETER GoogleSearch
    Send https://www.google.com/ as the navigation referer unless a Referer header is supplied.
  .PARAMETER WaitUntil
    Initial navigation readiness state.
  .PARAMETER NetworkIdle
    Also wait for Playwright's network-idle state after navigation.
  .PARAMETER WaitSelector
    CSS selector that must reach WaitSelectorState before returning.
  .PARAMETER WaitSelectorState
    Required selector state.
  .PARAMETER WaitMilliseconds
    Additional bounded delay after all readiness checks.
  .PARAMETER SolveCloudflare
    Enable best-effort Cloudflare challenge handling. Requires Stealth.
  .PARAMETER MaximumRetryCount
    Total GET navigation attempts.
  .PARAMETER RetryIntervalSeconds
    Delay between failed attempts.
  .PARAMETER Screenshot
    Save final page evidence to Outputs after success or failure.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory, Position = 0)][ValidateScript({ $_.Scheme -in 'http', 'https' })][uri]$Uri,
    [ValidateSet('Chromium')][string]$Browser = 'Chromium',
    [AllowEmptyString()][string]$Channel,
    [switch]$Headless,
    [string[]]$BlockUrlPattern = $Script:PlaywrightBlockedUrlPatterns,
    [switch]$Stealth,
    [switch]$DisableResources,
    [string[]]$BlockedDomain,
    [AllowEmptyString()][string]$UserAgent,
    [AllowEmptyString()][string]$Locale,
    [AllowEmptyString()][string]$TimezoneId,
    [Collections.IDictionary]$ExtraHTTPHeaders,
    [uri]$Proxy,
    [pscredential]$ProxyCredential,
    [AllowEmptyString()][string]$ProxyBypass,
    [switch]$IgnoreHTTPSErrors,
    [switch]$BlockWebRTC,
    [switch]$DisableWebGL,
    [switch]$DnsOverHttps,
    [string]$InitScriptPath,
    [string[]]$ExtraBrowserArgument,
    [Collections.IDictionary[]]$Cookie,
    [scriptblock]$PageSetup,
    [scriptblock]$PageAction,
    [string]$CaptureXhr,
    [bool]$GoogleSearch = $true,
    [ValidateSet('Commit', 'DOMContentLoaded', 'Load', 'NetworkIdle')][string]$WaitUntil = 'Load',
    [switch]$NetworkIdle,
    [string]$WaitSelector,
    [ValidateSet('Attached', 'Detached', 'Visible', 'Hidden')][string]$WaitSelectorState = 'Attached',
    [ValidateRange(0, [int]::MaxValue)][int]$WaitMilliseconds = 0,
    [switch]$SolveCloudflare,
    [ValidateRange(1, 10)][int]$MaximumRetryCount = 3,
    [ValidateRange(0, 300)][int]$RetryIntervalSeconds = 1,
    [switch]$Screenshot
  )

  if ($SolveCloudflare -and -not $Stealth) { throw 'SolveCloudflare requires the Patchright Stealth profile.' }
  if ($CaptureXhr) {
    try { $null = [regex]::new($CaptureXhr) } catch { throw "CaptureXhr is not a valid regular expression: $($_.Exception.Message)" }
  }
  $SessionParameters = Select-PlaywrightSessionParameter -BoundParameters $PSBoundParameters
  if (-not $SessionParameters.ContainsKey('Browser')) { $SessionParameters.Browser = $Browser }
  if (-not $SessionParameters.ContainsKey('BlockUrlPattern')) { $SessionParameters.BlockUrlPattern = $BlockUrlPattern }

  $Referer = $null
  $HasReferer = $false
  if ($ExtraHTTPHeaders) {
    foreach ($Key in $ExtraHTTPHeaders.Keys) {
      if ([string]$Key -ieq 'referer') { $HasReferer = $true; break }
    }
  }
  if ($GoogleSearch -and -not $HasReferer) { $Referer = 'https://www.google.com/' }

  $ScopedParameters = $SessionParameters.Clone()
  $ScopedParameters.Screenshot = $Screenshot
  $CloudflareDetector = ${function:Get-PlaywrightCloudflareChallengeType}
  $CloudflareHandler = ${function:Invoke-PlaywrightCloudflareChallenge}
  $OperationTimeoutMilliseconds = Get-PlaywrightOperationTimeout
  $ScopedParameters.ScriptBlock = {
    param($Page, $Context, $Browser, $Session)

    if ($Cookie) {
      $PlaywrightCookies = foreach ($CookieItem in $Cookie) {
        if (-not ($CookieItem.Keys -contains 'Name') -or -not ($CookieItem.Keys -contains 'Value')) {
          throw 'Each Playwright cookie requires Name and Value.'
        }
        $PlaywrightCookie = [Microsoft.Playwright.Cookie]::new()
        foreach ($PropertyName in 'Name', 'Value', 'Url', 'Domain', 'Path', 'Expires', 'HttpOnly', 'Secure', 'PartitionKey') {
          if ($CookieItem.Keys -contains $PropertyName) { $PlaywrightCookie.$PropertyName = $CookieItem[$PropertyName] }
        }
        if ($CookieItem.Keys -contains 'SameSite') {
          $PlaywrightCookie.SameSite = [Microsoft.Playwright.SameSiteAttribute][string]$CookieItem.SameSite
        }
        $PlaywrightCookie
      }
      $null = Wait-PlaywrightTask -Task ($Context.AddCookiesAsync([Microsoft.Playwright.Cookie[]]$PlaywrightCookies))
    }
    if ($PageSetup) { $null = & $PageSetup $Page $Context }

    $LastError = $null
    for ($Attempt = 1; $Attempt -le $MaximumRetryCount; $Attempt++) {
      $ResponseCapture = $null
      try {
        if ($CaptureXhr) { $ResponseCapture = $Session.BeginResponseCapture($CaptureXhr) }
        $GotoOptions = [Microsoft.Playwright.PageGotoOptions]::new()
        $GotoOptions.WaitUntil = [Microsoft.Playwright.WaitUntilState]$WaitUntil
        if ($Referer) { $GotoOptions.Referer = $Referer }
        $Response = Wait-PlaywrightTask -Task ($Page.GotoAsync($Uri.AbsoluteUri, $GotoOptions))
        if (-not $Response) { throw "Navigation returned no HTTP response for '$($Uri.AbsoluteUri)'." }

        if ($NetworkIdle) {
          $null = Wait-PlaywrightTask -Task ($Page.WaitForLoadStateAsync([Microsoft.Playwright.LoadState]::NetworkIdle))
        }
        $ChallengeDetected = $null
        if ($SolveCloudflare) {
          $ChallengeDetected = & $CloudflareHandler -Page $Page -TimeoutMilliseconds ([Math]::Max(60000, $OperationTimeoutMilliseconds))
        }
        if ($PageAction) { $null = & $PageAction $Page $Context $Response }
        if ($WaitSelector) {
          $SelectorOptions = [Microsoft.Playwright.PageWaitForSelectorOptions]::new()
          $SelectorOptions.State = [Microsoft.Playwright.WaitForSelectorState]$WaitSelectorState
          $null = Wait-PlaywrightTask -Task ($Page.WaitForSelectorAsync($WaitSelector, $SelectorOptions))
          if ($NetworkIdle) {
            $null = Wait-PlaywrightTask -Task ($Page.WaitForLoadStateAsync([Microsoft.Playwright.LoadState]::NetworkIdle))
          }
        }
        if ($WaitMilliseconds -gt 0) {
          $null = Wait-PlaywrightTask -Task ($Page.WaitForTimeoutAsync($WaitMilliseconds)) -TimeoutMilliseconds ($WaitMilliseconds + $OperationTimeoutMilliseconds)
        }

        $Content = [string](Wait-PlaywrightTask -Task $Page.ContentAsync())
        $BodyText = ''
        try { $BodyText = [string](Wait-PlaywrightTask -Task $Page.Locator('body').InnerTextAsync()) } catch {}
        $Headers = Wait-PlaywrightTask -Task $Response.AllHeadersAsync()
        $CapturedResponses = if ($ResponseCapture) {
          @(Wait-PlaywrightTask -Task $ResponseCapture.CompleteAsync())
        } else { @() }
        return [pscustomobject]@{
          Uri                       = [uri]$Page.Url
          StatusCode                = $Response.Status
          StatusDescription         = $Response.StatusText
          IsSuccessStatusCode       = $Response.Ok
          BrowserVersion            = $Browser.Version
          Headers                   = [Collections.Generic.Dictionary[string, string]]$Headers
          Content                   = $Content
          Text                      = $BodyText
          CloudflareChallenge       = $ChallengeDetected
          CloudflareChallengeActive = & $CloudflareDetector -Content $Content
          CapturedResponses         = $CapturedResponses
          AttemptCount              = $Attempt
        }
      } catch {
        if ($ResponseCapture) { $ResponseCapture.Dispose() }
        $LastError = $_
        if ($Attempt -ge $MaximumRetryCount) { break }
        try { $null = Wait-PlaywrightTask -Task ($Page.GotoAsync('about:blank')) } catch {}
        if ($RetryIntervalSeconds -gt 0) { Start-Sleep -Seconds $RetryIntervalSeconds }
      }
    }
    throw "Patchright failed to fetch '$($Uri.AbsoluteUri)' after ${MaximumRetryCount} attempts: $($LastError.Exception.Message)"
  }.GetNewClosure()

  Use-PlaywrightPage @ScopedParameters
}

function Stop-Playwright {
  <#
  .SYNOPSIS
    Force-stop and recycle the current task's managed Playwright browser.
  #>
  param ()

  $OwnerId = Get-PlaywrightLeaseOwnerId
  $Pool = Get-PlaywrightLeasePool -ExistingOnly
  if ($Pool -and $Pool.GetActiveLease($OwnerId)) { $null = Exit-PlaywrightLease -OwnerId $OwnerId -Recycle }
}

function Complete-DumplingsPlaywrightLease {
  <#
  .SYNOPSIS
    Complete a task lease and return its terminal outcome to the runner hook.
  .PARAMETER OwnerId
    Runner task owner identity.
  .PARAMETER Failed
    Recycle an active session because the task failed.
  #>
  param (
    [Parameter(Mandatory)][string]$OwnerId,
    [switch]$Failed
  )

  $Pool = Get-PlaywrightLeasePool -ExistingOnly
  if (-not $Pool) { return }
  if ($Pool.GetActiveLease($OwnerId)) { $null = Exit-PlaywrightLease -OwnerId $OwnerId -Failed:$Failed }
  $Removed = $null
  $null = $Script:PlaywrightLeases.TryRemove($OwnerId, [ref]$Removed)
  return ConvertTo-PlaywrightLeaseOutcome -Outcome ($Pool.TakeOutcome($OwnerId))
}

$ExecutionContext.SessionState.Module.OnRemove += {
  $Owner = Get-Variable -Name DumplingsPlaywrightLeaseOwnerId -Scope Global -ErrorAction SilentlyContinue
  if ($Owner -and $Owner.Value) {
    try { $null = Complete-DumplingsPlaywrightLease -OwnerId $Owner.Value -Failed } catch {}
  }
  if ($Script:StandalonePlaywrightPool) {
    $Script:StandalonePlaywrightPool.Dispose()
    $Script:StandalonePlaywrightPool = $null
  }
}

Export-ModuleMember -Function Import-PlaywrightRuntime, Install-PlaywrightBrowser, Wait-PlaywrightTask, Get-PlaywrightSession, Get-PlaywrightPage,
Open-PlaywrightPage, Read-PlaywrightPageContent, Read-PlaywrightLocator, Invoke-PlaywrightJavaScript, Use-PlaywrightPage,
Invoke-PlaywrightCloudflareChallenge, Invoke-PlaywrightFetch, Stop-Playwright, Exit-PlaywrightLease, Complete-DumplingsPlaywrightLease
