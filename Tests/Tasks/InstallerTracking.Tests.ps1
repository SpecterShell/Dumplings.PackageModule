# SPDX-License-Identifier: Apache-2.0
. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  . (Join-Path $PSScriptRoot '..\..\Index.ps1')
  function New-TrackingTask {
    param ([object[]]$Installers = @([ordered]@{ InstallerUrl = 'https://example.test/setup.exe'; Architecture = 'x64' }))
    [pscustomobject]@{
      Status         = [Collections.Generic.List[string]]::new()
      LastState      = [ordered]@{ Version = $null; Installer = @(); Locale = @() }
      CurrentState   = [ordered]@{ Version = $null; Installer = $Installers; Locale = @() }
      InstallerFiles = [ordered]@{}
    }
  }
  function Save-TrackingBaseline {
    param ($Task, $Options)
    $First = Get-PackageTaskInstallerUpdate -Task $Task -Options $Options
    $Task.LastState = Copy-Object $First.CandidateState
    return $First
  }
}

Describe 'Versionless installer tracking decisions' -Tag Unit {
  BeforeEach {
    $Global:TrackingBytes = [byte[]](1, 2, 3)
    $Global:TrackingHeaders = 'ETag: "one"'
    $Global:TrackingProbeHeaders = @{ ETag = @('"one"') }
    $Global:TrackingVersion = '2.0'
    $Global:TrackingVersions = @{}
    $Global:TrackingReadCalls = [Collections.Generic.List[string]]::new()
    $Task = New-TrackingTask
    $Options = @{
      Validator   = 'ETag'
      ReadVersion = {
        param ($Path, $Installer)
        $null = $Path
        $Global:TrackingReadCalls.Add($Installer.Architecture)
        if ($Global:TrackingVersions.Contains($Installer.Architecture)) { return $Global:TrackingVersions[$Installer.Architecture] }
        return $Global:TrackingVersion
      }
    }
    $ExistingTestFiles = @(Get-ChildItem $TestDrive -File).FullName
    Mock New-TempFile -ModuleName InstallerTracking { Join-Path $TestDrive ([guid]::NewGuid().ToString('N')) }
    Mock Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking {
      [pscustomobject]@{ StatusCode = 200; Headers = $Global:TrackingProbeHeaders; RequestUri = 'https://example.test/setup.exe' }
    }
    Mock Invoke-WinGetInstallerDownload -ModuleName InstallerTracking {
      param ($Uri, $DestinationPath)
      [IO.File]::WriteAllBytes($DestinationPath, $Global:TrackingBytes)
      [pscustomobject]@{
        DestinationPath = $DestinationPath; FinalUri = [string]$Uri; HttpStatusCode = 200
        ResponseHeaders = "HTTP/1.1 200 OK`r`n$Global:TrackingHeaders`r`n"
        Sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Global:TrackingBytes))
      }
    }
  }

  It 'initializes without probing or submitting, then skips unchanged bytes entirely' {
    $First = Save-TrackingBaseline $Task $Options
    $First.Outcome | Should -Be 'New'
    $First.ShouldWrite | Should -BeTrue
    $First.ShouldSubmit | Should -BeFalse
    $Second = Get-PackageTaskInstallerUpdate $Task $Options
    $Second.Outcome | Should -Be 'Unchanged'
    $Second.ShouldWrite | Should -BeFalse
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 1 -Exactly
    $Global:TrackingReadCalls.Count | Should -Be 1
  }

  It 'retains package metadata when accepting a new ETag for identical bytes' {
    $null = Save-TrackingBaseline $Task $Options
    $Task.LastState.Locale = @(@{ Locale = 'en-US'; Key = 'ReleaseNotes'; Value = 'Keep me' })
    $Task.LastState.Installer[0]['ProductCode'] = 'Keep product'
    $Before = Copy-Object $Task.LastState
    $Global:TrackingHeaders = 'ETag: "two"'
    $Global:TrackingProbeHeaders.ETag = @('"two"')
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Outcome | Should -Be 'EvidenceChanged'
    $Result.NeedsMetadata | Should -BeFalse
    $Result.CandidateState.Locale[0].Value | Should -Be 'Keep me'
    $Result.CandidateState.Installer[0].ProductCode | Should -Be 'Keep product'
    @($Result.CandidateState.InstallerTracking.Artifacts.Values)[0].AcceptedValues | Should -Be @('"one"', '"two"')
    Test-ObjectValueEqual $Task.LastState $Before | Should -BeTrue
    $Global:TrackingReadCalls.Count | Should -Be 1
  }

  It 'reports <Expected> when changed bytes resolve version <Version>' -ForEach @(
    @{ Version = '3.0'; Expected = 'Updated'; Submit = $true }
    @{ Version = '2.0'; Expected = 'Rebuilt'; Submit = $true }
    @{ Version = '1.0'; Expected = 'Rollbacked'; Submit = $false }
  ) {
    $null = Save-TrackingBaseline $Task $Options
    $Global:TrackingBytes = [byte[]](4, 5)
    $Global:TrackingVersion = $Version
    $Global:TrackingProbeHeaders.ETag = @('"two"')
    $Global:TrackingHeaders = 'ETag: "two"'
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Outcome | Should -Be $Expected
    $Result.ShouldSubmit | Should -Be $Submit
    if ($Submit) { @($Result.CandidateState.InstallerTracking.Artifacts.Values)[0].AcceptedValues | Should -Be @('"two"') }
    else { $Result.ShouldWrite | Should -BeFalse; foreach ($Path in $Result.Files.Values) { Test-Path $Path | Should -BeFalse } }
  }

  It 'permits explicit rollbacks and force bypasses fast and hash matches' {
    $null = Save-TrackingBaseline $Task $Options
    $Forced = Get-PackageTaskInstallerUpdate $Task $Options -Force
    $Forced.Outcome | Should -Be 'Forced'
    $Forced.ShouldSubmit | Should -BeTrue
    $Global:TrackingReadCalls.Count | Should -Be 2
    $Options.AllowRollback = $true
    $Global:TrackingProbeHeaders.ETag = @('"two"')
    $Global:TrackingBytes = [byte[]](5)
    $Global:TrackingVersion = '1.0'
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.ShouldSubmit | Should -BeTrue
    $Result.Outcome | Should -Be 'Rollbacked'
  }

  It 'compares opaque ETags case-sensitively and never substitutes a missing explicit validator' {
    $null = Save-TrackingBaseline $Task $Options
    $Global:TrackingProbeHeaders = @{ ETag = '"ONE"'; 'Content-Length' = '3' }
    $null = Get-PackageTaskInstallerUpdate $Task $Options
    $Global:TrackingProbeHeaders.Remove('ETag')
    $null = Get-PackageTaskInstallerUpdate $Task $Options
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 3 -Exactly
  }

  It 'uses download validators rather than caching a raced probe' {
    $null = Save-TrackingBaseline $Task $Options
    $Global:TrackingProbeHeaders.ETag = '"probe"'
    $Global:TrackingHeaders = 'ETag: "download"'
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Values = @($Result.CandidateState.InstallerTracking.Artifacts.Values)[0].AcceptedValues
    $Values | Should -Contain '"download"'
    $Values | Should -Not -Contain '"probe"'
    $Global:TrackingHeaders = ''
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    @($Result.CandidateState.InstallerTracking.Artifacts.Values)[0].AcceptedValues | Should -BeNullOrEmpty
  }

  It 'accepts validated DO files without trusting absent status or partial lengths' -ForEach @(
    @{ Status = $null; Headers = 'ETag: unproven'; Mode = 'ETag' }
    @{ Status = 206; Headers = 'Content-Length: 1'; Mode = 'ContentLength' }
  ) {
    $Options.Validator = $Mode
    Mock Invoke-WinGetInstallerDownload -ModuleName InstallerTracking {
      param($Uri, $DestinationPath)
      [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1, 2, 3))
      @{ DestinationPath = $DestinationPath; FinalUri = [string]$Uri; HttpStatusCode = $Status; ResponseHeaders = $Headers; Sha256 = 'A' * 64 }
    }
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Outcome | Should -Be 'New'
    $Record = @($Result.CandidateState.InstallerTracking.Artifacts.Values)[0]
    $Record.AcceptedValues | Should -BeNullOrEmpty
    $Record.ValidatorKind | Should -Be 'Hash'
  }

  It 'bounds accepted validator history to sixteen values for the same SHA256' {
    $null = Save-TrackingBaseline $Task $Options
    $Record = @($Task.LastState.InstallerTracking.Artifacts.Values)[0]
    $Record.AcceptedValues = @(1..16 | ForEach-Object { "tag$_" })
    $Global:TrackingProbeHeaders.ETag = 'tag17'
    $Global:TrackingHeaders = 'ETag: tag17'
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Values = @($Result.CandidateState.InstallerTracking.Artifacts.Values)[0].AcceptedValues
    $Values.Count | Should -Be 16
    $Values[0] | Should -Be 'tag2'
    $Values[-1] | Should -Be 'tag17'
  }

  It 'normalizes <Mode> and uses it for the explicitly chosen fast check' -ForEach @(
    @{ Mode = 'LastModified'; Header = 'Last-Modified'; Old = 'Tue, 22 Sep 2026 10:00:00 GMT'; New = 'Tue, 22 Sep 2026 12:00:00 +0200' }
    @{ Mode = 'ContentLength'; Header = 'Content-Length'; Old = '003'; New = '3' }
    @{ Mode = 'Header'; Header = 'Content-MD5'; Old = 'AbC+/=='; New = 'AbC+/==' }
  ) {
    $Options.Validator = $Mode
    $Options.HeaderName = $Header
    $Global:TrackingHeaders = "${Header}: $Old"
    $null = Save-TrackingBaseline $Task $Options
    $Global:TrackingProbeHeaders = @{ $Header = $New }
    (Get-PackageTaskInstallerUpdate $Task $Options).Outcome | Should -Be 'Unchanged'
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 1 -Exactly
  }

  It 'verifies regressed timestamps and malformed lengths rather than accepting them' {
    $Options.Validator = 'LastModified'
    $Global:TrackingHeaders = 'Last-Modified: Tue, 22 Sep 2026 10:00:00 GMT'
    $null = Save-TrackingBaseline $Task $Options
    $Global:TrackingProbeHeaders = @{ 'Last-Modified' = 'Mon, 21 Sep 2026 10:00:00 GMT' }
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Warnings -join ' ' | Should -Match 'older Last-Modified'
    $Options.Validator = 'ContentLength'
    $Global:TrackingProbeHeaders = @{ 'Content-Length' = '-1' }
    $null = Get-PackageTaskInstallerUpdate $Task $Options
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 3 -Exactly
  }

  It 'selects a compound checksum member and falls back to Hash with no usable headers' {
    $Options.Validator = 'Auto'
    $Options.HeaderName = 'x-goog-hash'
    $Options.SelectValue = { param($Values) @($Values) -split ',' | Where-Object { $_.Trim().StartsWith('md5=') } | ForEach-Object { $_.Trim().Substring(4) } }
    $Global:TrackingHeaders = "x-goog-hash: crc32c=abc,md5=base64==`r`nETag: misleading"
    $null = Save-TrackingBaseline $Task $Options
    $Global:TrackingProbeHeaders = @{ 'x-goog-hash' = @('md5=base64==', 'crc32c=xyz'); ETag = 'different' }
    (Get-PackageTaskInstallerUpdate $Task $Options).Outcome | Should -Be 'Unchanged'
    $Global:TrackingProbeHeaders = @{}
    $null = Get-PackageTaskInstallerUpdate $Task $Options
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 2 -Exactly
  }

  It 'Hash mode downloads every run but reads the version only when bytes change' {
    $Options.Validator = 'Hash'
    $null = Save-TrackingBaseline $Task $Options
    (Get-PackageTaskInstallerUpdate $Task $Options).Outcome | Should -Be 'Unchanged'
    Should -Invoke Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking -Times 0 -Exactly
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 2 -Exactly
    $Global:TrackingReadCalls.Count | Should -Be 1
  }

  It 'falls back from unsupported HEAD to GET, but rejects authentication failures' {
    $null = Save-TrackingBaseline $Task $Options
    Mock Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking {
      param($Method)
      if ($Method -eq 'HEAD') { return @{ StatusCode = 405; Headers = @{} } }
      return @{ StatusCode = 200; Headers = $Global:TrackingProbeHeaders }
    }
    (Get-PackageTaskInstallerUpdate $Task $Options).Outcome | Should -Be 'Unchanged'
    Should -Invoke Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' }
    Mock Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking { @{ StatusCode = 403; Headers = @{ ETag = '"one"' } } }
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*403*'
  }

  It 'shares downloads across architectures, preserves readers, and handles reordered entries' {
    $Task.CurrentState.Installer += [ordered]@{ Architecture = 'x86'; InstallerUrl = 'https://example.test/setup.exe' }
    $null = Save-TrackingBaseline $Task $Options
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 1 -Exactly
    $Global:TrackingReadCalls | Should -Be @('x64', 'x86')
    $Task.CurrentState.Installer = @($Task.CurrentState.Installer[1], $Task.CurrentState.Installer[0])
    (Get-PackageTaskInstallerUpdate $Task $Options).Outcome | Should -Be 'Unchanged'
  }

  It 'does not let an unchanged architecture hide a changed one and rejects inconsistent releases' {
    $Task.CurrentState.Installer += [ordered]@{ Architecture = 'x86'; InstallerUrl = 'https://example.test/x86.exe' }
    $null = Save-TrackingBaseline $Task $Options
    Mock Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking {
      param($Uri)
      @{ StatusCode = 200; Headers = @{ ETag = $(if ($Uri.AbsolutePath -eq '/x86.exe') { '"changed"' } else { '"one"' }) } }
    }
    $Global:TrackingBytes = [byte[]](5)
    $Global:TrackingVersion = '3.0'
    $Before = Copy-Object $Task.LastState
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*inconsistent*'
    Test-ObjectValueEqual $Task.LastState $Before | Should -BeTrue
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 3 -Exactly
  }

  It 'uses one downloaded payload for all shared entries when any entry lacks history' {
    $Task.CurrentState.Installer += [ordered]@{ Architecture = 'x86'; InstallerUrl = 'https://example.test/setup.exe' }
    $First = Save-TrackingBaseline $Task $Options
    $Task.LastState.InstallerTracking.Artifacts.Remove($First.Artifacts[1].Key)
    $Global:TrackingBytes = [byte[]](9, 8, 7)
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Outcome | Should -Be 'Rebuilt'
    @($Result.Artifacts.Sha256 | Sort-Object -Unique).Count | Should -Be 1
    @($Result.Artifacts | Where-Object Downloaded).Count | Should -Be 2
    $Result.Artifacts[0].Sha256 | Should -Not -Be $First.Artifacts[0].Sha256
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 2 -Exactly
    $Global:TrackingReadCalls | Should -Be @('x64', 'x86', 'x64', 'x86')
  }

  It 'invalidates validators when request headers change without persisting secrets' {
    $Options.Headers = @{ Authorization = 'Bearer SECRET'; 'X-Flavor' = 'one' }
    $null = Save-TrackingBaseline $Task $Options
    $Options.Headers['X-Flavor'] = 'two'
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 2 -Exactly
    $Serialized = $Result.CandidateState.InstallerTracking | ConvertTo-Json -Depth 10
    $Serialized | Should -Not -Match 'SECRET|Authorization|https://|[A-Z]:\\'
  }

  It 'preserves URL-only Changed behavior after confirming identical bytes' {
    $null = Save-TrackingBaseline $Task $Options
    $Task.CurrentState.Installer[0].InstallerUrl = 'https://example.test/new-name.exe'
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Outcome | Should -Be 'Changed'
    $Result.ShouldMessage | Should -BeTrue
    $Result.ShouldSubmit | Should -BeFalse
  }

  It 'rejects duplicate and query-based keys unless explicitly disambiguated' {
    $Task.CurrentState.Installer += Copy-Object $Task.CurrentState.Installer[0]
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*Ambiguous*'
    $Options.Installers = @(@{ InstallerIndex = 1; Key = 'second' })
    $Task.CurrentState.Installer[1].Architecture = { 'x86' }
    $Options.Installers[0].ReadVersion = { '2.0' }
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Artifacts.Count | Should -Be 2
  }

  It 'rejects unknown options, future state, and empty versions' {
    { Get-PackageTaskInstallerUpdate $Task @{ Validater = 'ETag' } } | Should -Throw '*Unknown*'
    $Task.LastState['InstallerTracking'] = @{ SchemaVersion = 2; Artifacts = @{} }
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*Unsupported*'
    $Task.LastState.Remove('InstallerTracking')
    $Options.ReadVersion = { '' }
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*empty version*'
  }

  It 'imports explicit legacy mappings without editing their accepted source object' {
    $First = Save-TrackingBaseline $Task $Options
    $Task.LastState.Remove('InstallerTracking')
    $Task.LastState['ETag'] = @('"one"')
    $Options.LegacyState = @{ ValidatorField = 'ETag' }
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Outcome | Should -Be 'EvidenceChanged'
    $Result.CandidateState.Contains('ETag') | Should -BeFalse
    $Task.LastState.ETag | Should -Be @('"one"')
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 2 -Exactly
    $Global:TrackingReadCalls.Count | Should -Be 2
    $Task.LastState.Installer[0].Remove('InstallerSha256')
    $null = Get-PackageTaskInstallerUpdate $Task $Options
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 3 -Exactly
  }

  It 'retains caller-owned custom downloads and removes only owned files after errors' {
    $Borrowed = Join-Path $TestDrive 'borrowed.exe'
    [IO.File]::WriteAllBytes($Borrowed, $Global:TrackingBytes)
    $Options.RequestKey = 'custom-source'
    $Options.Download = { param($Uri, $DestinationPath, $Settings) @{ Path = $Borrowed } }.GetNewClosure()
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.OwnedFiles | Should -Not -Contain $Borrowed
    Test-Path $Borrowed | Should -BeTrue
    $Options.ReadVersion = { throw 'version failed' }
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*version failed*'
    Test-Path $Borrowed | Should -BeTrue
    @(Get-ChildItem $TestDrive -File | Where-Object { $_.Name -match '^[0-9a-f]{32}$' -and $_.FullName -notin $ExistingTestFiles }).Count | Should -Be 0
  }

  It 'does not persist a hash supplied by a custom callback without hashing the file' {
    $Options.RequestKey = 'untrusted-hash'
    $Options.Download = { param($Uri, $DestinationPath) [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1)); @{ Path = $DestinationPath; Sha256 = 'A' * 64 } }
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Artifacts[0].Sha256 | Should -Not -Be ('A' * 64)
  }

  It 'propagates cancellation and removes partial downloads' {
    Mock Invoke-WinGetInstallerDownload -ModuleName InstallerTracking {
      param($DestinationPath)
      [IO.File]::WriteAllText($DestinationPath, 'partial')
      throw [OperationCanceledException]::new('cancelled')
    }
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*cancelled*'
    @(Get-ChildItem $TestDrive -File | Where-Object FullName -NotIn $ExistingTestFiles).Count | Should -Be 0
  }

  It 'preserves explicit RealVersion and rejects mutation of the input installer' {
    $Options.ReadVersion = { @{ Version = '2.0.4'; RealVersion = '2.0' } }
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.CandidateState.RealVersion | Should -Be '2.0'
    $Options.ReadVersion = { param($Path) [IO.File]::AppendAllText($Path, 'changed'); '2.0' }
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*modified*'
  }

  It 'invalidates resolved versions when the version reader changes' {
    $null = Save-TrackingBaseline $Task $Options
    $Options.ReadVersion = { '3.0' }
    (Get-PackageTaskInstallerUpdate $Task $Options).Outcome | Should -Be 'Updated'
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 2 -Exactly
  }

  It 'applies a corrected manifest version even when the comparison version is unchanged' {
    $null = Save-TrackingBaseline $Task $Options
    $Options.ReadVersion = { @{ Version = '2.0'; RealVersion = '2.0.0' } }
    $Result = Get-PackageTaskInstallerUpdate $Task $Options
    $Result.Outcome | Should -Be 'Updated'
    $Result.CandidateState.RealVersion | Should -Be '2.0.0'
  }

  It 'runs a synchronous custom probe and rejects malformed artifact history' {
    $Options.RequestKey = 'endpoint-v1'
    $Options.Probe = { param($Uri, $Settings) @{ StatusCode = 200; Headers = @{ ETag = '"one"' }; RequestUri = [string]$Uri } }
    $null = Save-TrackingBaseline $Task $Options
    (Get-PackageTaskInstallerUpdate $Task $Options).Outcome | Should -Be 'Unchanged'
    Should -Invoke Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking -Times 0 -Exactly
    $Key = @($Task.LastState.InstallerTracking.Artifacts.Keys)[0]
    $Task.LastState.InstallerTracking.Artifacts[$Key] = 'invalid'
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*Malformed*'
  }

  It 'normalizes typed legacy dates without relying on the current culture' {
    InModuleScope InstallerTracking {
      (ConvertTo-InstallerTrackingValidator LastModified ([datetime]::new(2026, 9, 22, 10, 0, 0, [DateTimeKind]::Utc))) | Should -Be '2026-09-22T10:00:00.0000000+00:00'
      (ConvertTo-InstallerTrackingValidator ETag "bad`nvalue") | Should -BeNullOrEmpty
    }
    $Options.LegacyState = @{ ValidatorField = 'Version' }
    { Get-PackageTaskInstallerUpdate $Task $Options } | Should -Throw '*dedicated validator*'
    Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times 0 -Exactly
  }
}

Describe 'PackageTask installer tracking lifecycle' -Tag Unit {
  BeforeAll {
    function global:Write-Log { param($Object, $Level) }
    if (-not ('InstallerTrackingLifecycleTask' -as [type])) {
      Invoke-Expression @'
class InstallerTrackingLifecycleTask : PackageTask {
  [int]$Prints
  [int]$Writes
  [int]$Messages
  [int]$Submissions
  InstallerTrackingLifecycleTask([Collections.IDictionary]$Properties) : base($Properties) {}
  [void] Print() { $this.Prints++ }
  [void] Write() { if ($Global:DumplingsPreference['EnableWrite']) { $this.Writes++ } }
  [void] Message() { if ($Global:DumplingsPreference['EnableMessage']) { $this.Messages++ } }
  [void] Submit() { if ($Global:DumplingsPreference['EnableSubmit']) { $this.Submissions++ } }
}
'@
    }
    function New-LifecycleTask {
      $Directory = New-Item -Path (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -ItemType Directory
      [IO.File]::WriteAllText((Join-Path $Directory.FullName 'Script.ps1'), '')
      $Task = [InstallerTrackingLifecycleTask]::new(@{ Name = 'Tracking'; Path = $Directory.FullName; Config = @{ WinGetIdentifier = 'Example.Package' } })
      $Task.CurrentState.Installer += [ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup.exe' }
      return $Task
    }
  }
  BeforeEach {
    $Global:DumplingsPreference = @{ EnableWrite = $true; EnableMessage = $true; EnableSubmit = $true }
    $Options = @{ Validator = 'Hash'; ReadVersion = { '2.0' } }
    Mock New-TempFile -ModuleName InstallerTracking { Join-Path $TestDrive ([guid]::NewGuid().ToString('N')) }
    Mock Invoke-WinGetInstallerDownload -ModuleName InstallerTracking {
      param($Uri, $DestinationPath)
      [IO.File]::WriteAllText($DestinationPath, 'installer')
      [pscustomobject]@{ DestinationPath = $DestinationPath; Sha256 = 'B' * 64; FinalUri = [string]$Uri; HttpStatusCode = 200; ResponseHeaders = '' }
    }
  }
  It 'does not publish while checking and completes a new task exactly once' {
    $Task = New-LifecycleTask
    $Task.MessageEnabled = $true
    $Result = $Task.CheckInstallerUpdates($Options)
    $Task.Messages | Should -Be 0
    $Task.Writes | Should -Be 0
    { $Task.CheckInstallerUpdates($Options) } | Should -Throw '*pending*'
    $Task.CompleteInstallerUpdates($Result)
    $Task.CompleteInstallerUpdates($Result)
    $Task.Prints | Should -Be 1
    $Task.Writes | Should -Be 1
    $Task.Messages | Should -Be 0
    $Task.Submissions | Should -Be 0
    $Task.Dispose()
    foreach ($Path in $Result.Files.Values) { Test-Path $Path | Should -BeFalse }
  }
  It 'rejects foreign decisions, preserves PR policy, and honors disabled gates' {
    $Task = New-LifecycleTask
    $Other = New-LifecycleTask
    $Result = $Task.CheckInstallerUpdates($Options)
    { $Other.CompleteInstallerUpdates($Result) } | Should -Throw '*another task*'
    $Task.CompleteInstallerUpdates($Result)
    $Task.LastState = Copy-Object $Task.CurrentState
    $Task.Status.Clear()
    $Global:DumplingsPreference = @{ Force = $true }
    $Result = $Task.CheckInstallerUpdates($Options)
    $Task.CompleteInstallerUpdates($Result)
    $Task.Config.Contains('IgnorePRCheck') | Should -BeFalse
    $Task.Submissions | Should -Be 0
    $Task.Messages | Should -Be 0
    $Task.Writes | Should -Be 1
    $Task.Dispose()
  }
  It 'retains borrowed custom files through successful and failed checks' {
    $Task = New-LifecycleTask
    $Borrowed = Join-Path $TestDrive 'external.exe'
    [IO.File]::WriteAllText($Borrowed, 'caller-owned')
    $Options.RequestKey = 'borrowed'
    $Options.Download = { param($Uri, $DestinationPath) @{ Path = $Borrowed } }.GetNewClosure()
    $Result = $Task.CheckInstallerUpdates($Options)
    $Task.CompleteInstallerUpdates($Result)
    $Task.Dispose()
    Test-Path $Borrowed | Should -BeTrue
    $Options.ReadVersion = { throw 'failed' }
    { $Task.CheckInstallerUpdates($Options) } | Should -Throw '*failed*'
    $Task.Dispose()
    Test-Path $Borrowed | Should -BeTrue
  }

  It 'keeps another authors PR blocking a same-version rebuild' {
    $Task = New-LifecycleTask
    $First = $Task.CheckInstallerUpdates($Options)
    $Task.CompleteInstallerUpdates($First)
    $Task.LastState = Copy-Object $Task.CurrentState
    $Task.Status.Clear()
    Mock Invoke-WinGetInstallerDownload -ModuleName InstallerTracking {
      param($Uri, $DestinationPath)
      [IO.File]::WriteAllText($DestinationPath, 'replacement')
      @{ DestinationPath = $DestinationPath; Sha256 = 'C' * 64; FinalUri = [string]$Uri; HttpStatusCode = 200; ResponseHeaders = '' }
    }
    $Result = $Task.CheckInstallerUpdates($Options)
    $Result.Outcome | Should -Be 'Rebuilt'
    $Result.ShouldSubmit | Should -BeTrue
    $Global:DumplingsOutput = $TestDrive
    $Global:DumplingsPreference.WinGetOriginRepoOwner = 'TestBot'
    Mock Get-WinGetLocalRepoPath -ModuleName WinGetSubmission { $null }
    Mock Get-WinGetGitHubBranch -ModuleName WinGetSubmission { @{ object = @{ sha = 'A' * 40 } } }
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { '2.0' }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetSubmission { @{ login = 'TestBot' } }
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission {
      @{ items = @(@{ number = 42; title = 'Update: Example.Package version 2.0'; html_url = 'https://example.test/pr/42'; user = @{ login = 'OtherAuthor' } }) }
    }
    Mock Read-WinGetGitHubManifests -ModuleName WinGetSubmission { throw 'Should not reach manifest reads' }
    try {
      { Send-WinGetManifest -Task $Task } | Should -Throw '*process will be terminated*'
      Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetSubmission -Times 0 -Exactly
      $Task.Config.Contains('IgnorePRCheck') | Should -BeFalse
    } finally { $Task.Dispose() }
  }
  AfterAll { Remove-Item Function:\Write-Log -ErrorAction Ignore }
}

AfterAll {
  Remove-Variable TrackingBytes, TrackingHeaders, TrackingProbeHeaders, TrackingVersion, TrackingVersions, TrackingReadCalls -Scope Global -ErrorAction Ignore
}
