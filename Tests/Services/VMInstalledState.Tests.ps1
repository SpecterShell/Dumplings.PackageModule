. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  $Script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsRepositoryRoot '.'))
  $Script:GuestScript = Join-Path $Script:RepositoryRoot '.agents\skills\analyze-winget-installer\scripts\Get-WinGetVMInstalledState.ps1'
  $Script:HostScript = Join-Path $Script:RepositoryRoot '.agents\skills\analyze-winget-installer\scripts\Invoke-WinGetVMInstalledState.ps1'

  function Get-VM {}
  function Get-VMIntegrationService {}
  function Copy-VMFile {}

  function Get-VMTestSnapshot {
    param(
      [Parameter(Mandatory)][string]$Phase,
      [object[]]$ARPEntries = @(),
      [object[]]$Protocols = @(),
      [object[]]$FileExtensions = @(),
      [object[]]$EnvironmentPaths = @()
    )
    [pscustomobject][ordered]@{
      SchemaVersion             = 1
      Phase                     = $Phase
      CapturedAtUtc             = '2026-07-12T00:00:00.0000000Z'
      ComputerName              = 'TESTVM'
      UserName                  = 'TESTVM\Tester'
      UserSid                   = 'S-1-5-21-1'
      IsElevated                = $true
      OperatingSystem           = 'Windows'
      Is64BitOperatingSystem    = $true
      Is64BitProcess            = $true
      ARPEntries                = $ARPEntries
      ProtocolAssociations      = $Protocols
      FileExtensionAssociations = $FileExtensions
      EnvironmentPaths          = $EnvironmentPaths
    }
  }
}

Describe 'VM installed-state comparison script' {
  BeforeEach {
    $Script:BeforePath = Join-Path $TestDrive 'BeforeInstall.json'
    $Script:AfterPath = Join-Path $TestDrive 'AfterInstall.json'
    $Script:OutputPath = Join-Path $TestDrive 'Comparison.json'

    $Before = Get-VMTestSnapshot -Phase BeforeInstall -ARPEntries @(
      [pscustomobject][ordered]@{ Identity = 'ARP|HKLM|Registry64|Product'; DisplayVersion = '1.0'; IsVisible = $true; IsSystemComponent = $false },
      [pscustomobject][ordered]@{ Identity = 'ARP|HKCU|Default|Removed'; DisplayVersion = '1.0'; IsVisible = $true; IsSystemComponent = $false }
    ) -Protocols @(
      [pscustomobject][ordered]@{ Identity = 'Protocol|HKCU|Default|Classes|sample'; Source = 'Classes'; Name = 'sample'; ClassDetails = [pscustomobject]@{ Command = 'old.exe "%1"' } }
    ) -EnvironmentPaths @(
      [pscustomobject][ordered]@{ Identity = 'EnvironmentPath|machine|c:\windows'; Scope = 'machine'; ExpandedPath = 'C:\Windows'; CommandCandidates = @() }
    )
    $After = Get-VMTestSnapshot -Phase AfterInstall -ARPEntries @(
      [pscustomobject][ordered]@{ Identity = 'ARP|HKLM|Registry64|Product'; DisplayVersion = '2.0'; IsVisible = $true; IsSystemComponent = $false },
      [pscustomobject][ordered]@{ Identity = 'ARP|HKLM|Registry32|HiddenMsi'; DisplayVersion = '2.0'; IsVisible = $false; IsSystemComponent = $true; WindowsInstaller = $true }
    ) -Protocols @(
      [pscustomobject][ordered]@{ Identity = 'Protocol|HKCU|Default|Classes|sample'; Source = 'Classes'; Name = 'sample'; ClassDetails = [pscustomobject]@{ Command = 'new.exe "%1"' } }
    ) -FileExtensions @(
      [pscustomobject][ordered]@{ Identity = 'FileExtension|HKLM|Registry64|Capabilities|Sample App|.sample'; Source = 'RegisteredApplications'; Name = 'sample'; DefaultProgId = 'Sample.Document'; ApplicationName = 'Sample App' }
    ) -EnvironmentPaths @(
      [pscustomobject][ordered]@{ Identity = 'EnvironmentPath|machine|c:\windows'; Scope = 'machine'; ExpandedPath = 'C:\Windows'; CommandCandidates = @() },
      [pscustomobject][ordered]@{ Identity = 'EnvironmentPath|machine|c:\program files\sample\bin'; Scope = 'machine'; ExpandedPath = 'C:\Program Files\Sample\bin'; CommandCandidates = @('sample') }
    )

    [IO.File]::WriteAllText($Script:BeforePath, ($Before | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($Script:AfterPath, ($After | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
  }

  It 'reports added, modified, removed, hidden, protocol, and capability changes' {
    & $Script:GuestScript -Action Compare -BeforePath $Script:BeforePath -AfterPath $Script:AfterPath -OutputPath $Script:OutputPath
    $Result = Get-Content -LiteralPath $Script:OutputPath -Raw | ConvertFrom-Json

    $Result.Summary.ARPChanges | Should -Be 3
    $Result.Summary.VisibleARPChanges | Should -Be 2
    $Result.Summary.HiddenARPChanges | Should -Be 1
    $Result.ARPChanges.Status | Should -Be @('Added', 'Modified', 'Removed')
    $Result.HiddenARPChanges[0].After.IsSystemComponent | Should -BeTrue
    $Result.ProtocolChanges[0].Status | Should -Be 'Modified'
    $Result.ProtocolChanges[0].After.ClassDetails.Command | Should -Be 'new.exe "%1"'
    $Result.FileExtensionChanges[0].Status | Should -Be 'Added'
    $Result.FileExtensionChanges[0].After.Source | Should -Be 'RegisteredApplications'
    $Result.Summary.EnvironmentPathChanges | Should -Be 1
    $Result.EnvironmentPathChanges[0].Status | Should -Be 'Added'
    $Result.EnvironmentPathChanges[0].After.CommandCandidates | Should -Contain 'sample'
  }

  It 'orders comparison output by status and stable identity' {
    & $Script:GuestScript -Action Compare -BeforePath $Script:BeforePath -AfterPath $Script:AfterPath -OutputPath $Script:OutputPath
    $Result = Get-Content -LiteralPath $Script:OutputPath -Raw | ConvertFrom-Json

    $Result.ARPChanges.Identity | Should -Be @(
      'ARP|HKLM|Registry32|HiddenMsi',
      'ARP|HKLM|Registry64|Product',
      'ARP|HKCU|Default|Removed'
    )
  }

  It 'runs comparison under Windows PowerShell 5.1' {
    $WindowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Test-Path -LiteralPath $WindowsPowerShell | Should -BeTrue
    $WindowsPowerShellOutput = Join-Path $TestDrive 'WindowsPowerShellComparison.json'
    & $WindowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $Script:GuestScript -Action Compare -BeforePath $Script:BeforePath -AfterPath $Script:AfterPath -OutputPath $WindowsPowerShellOutput

    $LASTEXITCODE | Should -Be 0
    Test-Path -LiteralPath $WindowsPowerShellOutput | Should -BeTrue
    (Get-Content -LiteralPath $WindowsPowerShellOutput -Raw | ConvertFrom-Json).Summary.ARPChanges | Should -Be 3
  }

  It 'collects requested and adjacent logs with the installer exit code' {
    $LogSource = Join-Path $TestDrive 'InstallerLogs'
    $EvidenceDirectory = Join-Path $TestDrive 'CollectedLogs'
    $ResultPath = Join-Path $TestDrive 'InstallerLogs.json'
    $null = New-Item -ItemType Directory -Path $LogSource -Force
    $RequestedLog = Join-Path $LogSource 'installer.log'
    Set-Content -LiteralPath $RequestedLog -Value @('starting', 'completed')
    Set-Content -LiteralPath (Join-Path $LogSource 'installer-detail.log') -Value @('detail')
    Set-Content -LiteralPath (Join-Path $LogSource 'unrelated.log') -Value @('unrelated')

    & $Script:GuestScript -Action CollectLogs -OutputPath $ResultPath -LogPath $RequestedLog -SinceUtc ([DateTime]::UtcNow.AddMinutes(-1)) -LogOutputDirectory $EvidenceDirectory -InstallerExitCode 0 -InstallerMode silent -IncludeTemporaryLogs:$false
    $Result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json

    $Result.InstallerExitCode | Should -Be 0
    $Result.ExitCodeIsZero | Should -BeTrue
    $Result.InstallerTimedOut | Should -BeFalse
    $Result.Files | Should -HaveCount 2
    $Result.Files[0].Origin | Should -Be 'RequestedFile'
    @($Result.Files | Where-Object Copied) | Should -HaveCount 2
    @($Result.Files.TailLines) | Should -Contain 'completed'
    Get-ChildItem -LiteralPath $EvidenceDirectory -File | Should -HaveCount 2
  }

  It 'keeps a requested log directory isolated from its parent directory' {
    $LogParent = Join-Path $TestDrive 'LogParent'
    $LogSource = Join-Path $LogParent 'RequestedLogs'
    $EvidenceDirectory = Join-Path $TestDrive 'DirectoryEvidence'
    $ResultPath = Join-Path $TestDrive 'DirectoryLogs.json'
    $null = New-Item -ItemType Directory -Path $LogSource -Force
    Set-Content -LiteralPath (Join-Path $LogSource 'installer.log') -Value 'requested'
    Set-Content -LiteralPath (Join-Path $LogParent 'unrelated.log') -Value 'unrelated'

    & $Script:GuestScript -Action CollectLogs -OutputPath $ResultPath -LogPath $LogSource -SinceUtc ([DateTime]::UtcNow.AddMinutes(-1)) -LogOutputDirectory $EvidenceDirectory -InstallerMode silent -IncludeTemporaryLogs:$false
    $Result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json

    $Result.Files | Should -HaveCount 1
    $Result.Files[0].Origin | Should -Be 'RequestedDirectory'
    $Result.Files[0].SourcePath | Should -Be (Join-Path $LogSource 'installer.log')
  }

  It 'collects installer logs under Windows PowerShell 5.1' {
    $WindowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $LogSource = Join-Path $TestDrive 'WindowsPowerShellLogs'
    $EvidenceDirectory = Join-Path $TestDrive 'WindowsPowerShellLogEvidence'
    $ResultPath = Join-Path $TestDrive 'WindowsPowerShellLogs.json'
    $null = New-Item -ItemType Directory -Path $LogSource -Force
    $RequestedLog = Join-Path $LogSource 'installer.log'
    Set-Content -LiteralPath $RequestedLog -Value 'completed'
    $SinceUtc = [DateTime]::UtcNow.AddMinutes(-1).ToString('o')
    $Command = "& '$Script:GuestScript' -Action CollectLogs -OutputPath '$ResultPath' -LogPath '$RequestedLog' -SinceUtc '$SinceUtc' -LogOutputDirectory '$EvidenceDirectory' -InstallerExitCode 0 -IncludeTemporaryLogs:`$false"

    & $WindowsPowerShell -NoProfile -ExecutionPolicy Bypass -Command $Command
    $Result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json

    $LASTEXITCODE | Should -Be 0
    $Result.InstallerExitCode | Should -Be 0
    @($Result.Files | Where-Object Copied) | Should -HaveCount 1
  }
}

Describe 'Hyper-V installed-state host controller' {
  It 'imports the inbox Hyper-V module natively in PowerShell Core' {
    $Text = Get-Content -LiteralPath $Script:HostScript -Raw
    $Text | Should -Match ([regex]::Escape("`$env:PSModulePath += ';C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'"))
    $Text | Should -Match ([regex]::Escape('Import-Module Hyper-V -PassThru'))
    $Text | Should -Not -Match ([regex]::Escape('-UseWindowsPowerShell'))
  }

  It 'stages and captures evidence without installer execution code' {
    $Text = Get-Content -LiteralPath $Script:HostScript -Raw
    $Text | Should -Match '\bCopy-VMFile\b'
    $Text | Should -Match 'Invoke-Command\s+-VMName'
    $Text | Should -Not -Match '\bStart-Process\b|\bInvoke-Item\b'
  }

  It 'stages the collector with mocked Hyper-V integration services' {
    Mock Import-Module { [pscustomobject]@{ Name = 'Hyper-V' } }
    Mock Get-VM { [pscustomobject]@{ Name = 'TestVM'; State = 'Running' } }
    Mock Get-VMIntegrationService { [pscustomobject]@{ Name = 'Guest Service Interface'; Enabled = $true } }
    Mock Copy-VMFile {}

    $Result = & $Script:HostScript -Action Stage -VMName TestVM

    $Result.GuestScriptPath | Should -Be 'C:\DumplingsValidation\Get-WinGetVMInstalledState.ps1'
    Should -Invoke Copy-VMFile -Times 1 -Exactly
  }

  It 'retrieves capture JSON through mocked PowerShell Direct' {
    Mock Import-Module { [pscustomobject]@{ Name = 'Hyper-V' } }
    Mock Get-VM { [pscustomobject]@{ Name = 'TestVM'; State = 'Running' } }
    Mock Get-VMIntegrationService { [pscustomobject]@{ Name = 'Guest Service Interface'; Enabled = $true } }
    Mock Copy-VMFile {}
    Mock Invoke-Command { '{"SchemaVersion":1,"Phase":"BeforeInstall","ARPEntries":[{"Identity":"ARP|HKLM|Registry64|Existing"}],"ProtocolAssociations":[],"FileExtensionAssociations":[]}' }
    $Credential = [pscredential]::new('Tester', [securestring]::new())
    $OutputDirectory = Join-Path $TestDrive 'HostCapture'

    $Result = & $Script:HostScript -Action Capture -VMName TestVM -Phase BeforeInstall -Credential $Credential -OutputDirectory $OutputDirectory

    Test-Path -LiteralPath $Result.HostOutputPath | Should -BeTrue
    (Get-Content -LiteralPath $Result.HostOutputPath -Raw | ConvertFrom-Json).Phase | Should -Be 'BeforeInstall'
    Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter { $VMName -eq 'TestVM' }
  }

  It 'retrieves bounded installer logs and process evidence through PowerShell Direct' {
    Mock Import-Module { [pscustomobject]@{ Name = 'Hyper-V' } }
    Mock Get-VM { [pscustomobject]@{ Name = 'TestVM'; State = 'Running' } }
    Mock Get-VMIntegrationService { [pscustomobject]@{ Name = 'Guest Service Interface'; Enabled = $true } }
    Mock Copy-VMFile {}
    Mock New-PSSession {}
    Mock Invoke-Command { '{"SchemaVersion":1,"InstallerMode":"silent","InstallerExitCode":0,"InstallerTimedOut":false,"Files":[{"Copied":true,"EvidenceFileName":"0001-installer.log"}],"Warnings":[]}' }
    Mock Copy-Item {}
    Mock Remove-PSSession {}
    $Credential = [pscredential]::new('Tester', [securestring]::new())
    $OutputDirectory = Join-Path $TestDrive 'HostLogCapture'

    $Result = & $Script:HostScript -Action CollectLogs -VMName TestVM -Phase Silent -Credential $Credential -OutputDirectory $OutputDirectory -LogPath 'C:\Logs\installer.log' -InstallerStartedAtUtc ([DateTime]::UtcNow.AddMinutes(-1)) -InstallerExitCode 0 -SkipLogFileTransfer

    $Result.InstallerExitCode | Should -Be 0
    $Result.FileCount | Should -Be 1
    Test-Path -LiteralPath $Result.HostOutputPath | Should -BeTrue
    $Result.LogFilesTransferred | Should -BeFalse
    Should -Invoke New-PSSession -Times 0 -Exactly
    Should -Invoke Copy-Item -Times 0 -Exactly
    Should -Invoke Remove-PSSession -Times 0 -Exactly
  }

  It 'rejects an empty capture returned by the guest collector' {
    Mock Import-Module { [pscustomobject]@{ Name = 'Hyper-V' } }
    Mock Get-VM { [pscustomobject]@{ Name = 'TestVM'; State = 'Running' } }
    Mock Get-VMIntegrationService { [pscustomobject]@{ Name = 'Guest Service Interface'; Enabled = $true } }
    Mock Copy-VMFile {}
    Mock Invoke-Command { '{"SchemaVersion":1,"Phase":"BeforeInstall","ARPEntries":[],"ProtocolAssociations":[],"FileExtensionAssociations":[]}' }
    $Credential = [pscredential]::new('Tester', [securestring]::new())

    { & $Script:HostScript -Action Capture -VMName TestVM -Phase BeforeInstall -Credential $Credential -OutputDirectory (Join-Path $TestDrive 'EmptyCapture') } | Should -Throw '*empty installed-state snapshot*'
  }
}
