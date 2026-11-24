. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Index.ps1') -Force

  function global:Write-Log {
    param ($Object, $Level)
    $null = $Object, $Level
  }

  function global:Send-WinGetManifest {
    param ($Task, [switch]$SkipInstallerAnalysis)
    if ($Global:SubmissionTestShouldFail) { throw 'synthetic submission failure' }
    $Global:SubmissionTestCalls.Add($Task.Name)
    $Global:SubmissionTestSkipInstallerAnalysis.Add($SkipInstallerAnalysis.IsPresent)
  }

  function New-SubmissionTestTask {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][System.Collections.IDictionary]$Config
    )

    $TaskPath = Join-Path $TestDrive $Name
    $null = New-Item -Path $TaskPath -ItemType Directory -Force
    Set-Content -LiteralPath (Join-Path $TaskPath 'Script.ps1') -Value ''
    [PackageTask]::new([ordered]@{ Name = $Name; Path = $TaskPath; Config = $Config })
  }

  function New-CheckTestTask {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$LastInstallerUrl,
      [Parameter(Mandatory)][string]$CurrentInstallerUrl,
      [System.Collections.IDictionary]$Config = [ordered]@{}
    )

    $TaskPath = Join-Path $TestDrive $Name
    $null = New-Item -Path $TaskPath -ItemType Directory -Force
    Set-Content -LiteralPath (Join-Path $TaskPath 'Script.ps1') -Value ''
    [ordered]@{
      Version   = '1.0.0'
      Installer = @([ordered]@{ InstallerUrl = $LastInstallerUrl })
      Locale    = @()
    } | ConvertTo-Yaml | Set-Content -LiteralPath (Join-Path $TaskPath 'State.yaml')

    $Task = [PackageTask]::new([ordered]@{ Name = $Name; Path = $TaskPath; Config = $Config })
    $Task.CurrentState.Version = '2.0.0'
    $Task.CurrentState.Installer += [ordered]@{ InstallerUrl = $CurrentInstallerUrl }
    return $Task
  }
}

Describe 'PackageTask WinGet submission claims' -Tag Unit {
  BeforeEach {
    $Global:DumplingsPreference = [ordered]@{ EnableSubmit = $true }
    $Global:DumplingsStorage = [hashtable]::Synchronized(@{})
    $Global:DumplingsStorage['__DumplingsWinGetSubmissionClaims'] =
    [Collections.Concurrent.ConcurrentDictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Global:SubmissionTestCalls = [Collections.Generic.List[string]]::new()
    $Global:SubmissionTestSkipInstallerAnalysis = [Collections.Generic.List[bool]]::new()
    $Global:SubmissionTestShouldFail = $false
  }

  It 'allows one task to claim an identifier and skips a different task case-insensitively' {
    $First = New-SubmissionTestTask -Name First -Config ([ordered]@{ WinGetIdentifier = 'Example.Package' })
    $Second = New-SubmissionTestTask -Name Second -Config ([ordered]@{ WinGetIdentifier = 'example.package' })

    $First.Submit()
    $Second.Submit()

    $Global:SubmissionTestCalls.ToArray() | Should -Be @('First')
    $Second.Logs -join "`n" | Should -Match "task 'First' already owns"
  }

  It 'allows the owning task to submit the same identifier again' {
    $Task = New-SubmissionTestTask -Name Owner -Config ([ordered]@{ WinGetIdentifier = 'Example.Package' })

    $Task.Submit()
    $Task.Submit()

    $Global:SubmissionTestCalls.ToArray() | Should -Be @('Owner', 'Owner')
  }

  It 'claims the effective new identifier using submission precedence' {
    $Task = New-SubmissionTestTask -Name Alias -Config ([ordered]@{
        WinGetIdentifier           = 'Example.Reference'
        WinGetPackageIdentifier    = 'Example.PackageReference'
        WinGetNewIdentifier        = 'Example.LegacyTarget'
        WinGetNewPackageIdentifier = 'Example.Target'
      })

    $Task.Submit()

    $Global:DumplingsStorage['__DumplingsWinGetSubmissionClaims'].ContainsKey('Example.Target') | Should -BeTrue
    $Global:DumplingsStorage['__DumplingsWinGetSubmissionClaims'].Count | Should -Be 1
  }

  It 'allows unrelated identifiers to submit independently' {
    (New-SubmissionTestTask -Name First -Config ([ordered]@{ WinGetIdentifier = 'Example.One' })).Submit()
    (New-SubmissionTestTask -Name Second -Config ([ordered]@{ WinGetIdentifier = 'Example.Two' })).Submit()

    $Global:SubmissionTestCalls.ToArray() | Should -Be @('First', 'Second')
  }

  It 'retains the claim after submission failure' {
    $First = New-SubmissionTestTask -Name First -Config ([ordered]@{ WinGetIdentifier = 'Example.Package' })
    $Second = New-SubmissionTestTask -Name Second -Config ([ordered]@{ WinGetIdentifier = 'Example.Package' })
    $Global:SubmissionTestShouldFail = $true

    { $First.Submit() } | Should -Throw '*synthetic submission failure*'
    $Global:SubmissionTestShouldFail = $false
    $Second.Submit()

    $Global:SubmissionTestCalls | Should -BeNullOrEmpty
    $Global:DumplingsStorage['__DumplingsWinGetSubmissionClaims']['Example.Package'] | Should -BeExactly 'First'
  }

  It 'passes the global installer-analysis skip preference to submission' {
    $Global:DumplingsPreference.SkipInstallerAnalysis = $true
    $Task = New-SubmissionTestTask -Name GlobalSkip -Config ([ordered]@{ WinGetIdentifier = 'Example.GlobalSkip' })

    $Task.Submit()

    $Global:SubmissionTestSkipInstallerAnalysis.ToArray() | Should -Be @($true)
  }

  It 'passes the task installer-analysis skip setting to submission' {
    $Task = New-SubmissionTestTask -Name TaskSkip -Config ([ordered]@{
        WinGetIdentifier      = 'Example.TaskSkip'
        SkipInstallerAnalysis = $true
      })

    $Task.Submit()

    $Global:SubmissionTestSkipInstallerAnalysis.ToArray() | Should -Be @($true)
  }
}

Describe 'PackageTask Check domain-change warning' -Tag Unit {
  BeforeEach {
    $Global:DumplingsPreference = [ordered]@{}
  }

  It 'warns when the installer source identity changes' {
    $Task = New-CheckTestTask -Name DomainChange `
      -LastInstallerUrl 'https://github.com/example/old/releases/download/v1/app.exe' `
      -CurrentInstallerUrl 'https://github.com/example/new/releases/download/v2/app.exe'

    $null = $Task.Check()

    $Task.Logs | Should -Contain "⚠️ [Installer #1/1] The installer source identity 'github.com/example/old' changed to 'github.com/example/new'"
  }

  It 'labels a changed source with its current installer position' {
    $Task = New-CheckTestTask -Name MultipleInstallers `
      -LastInstallerUrl 'https://download.invantive.com/setup-x64.msi' `
      -CurrentInstallerUrl 'https://download.invantive.com/setup-x64-new.msi'
    $Task.LastState.Installer += [ordered]@{ InstallerUrl = 'https://download.invantive.com/setup-arm64.msi' }
    $Task.CurrentState.Installer += [ordered]@{ InstallerUrl = 'https://download.invantive.eu/setup-arm64.msi' }

    $null = $Task.Check()

    $Task.Logs | Should -Contain "⚠️ [Installer #2/2] The installer source identity 'download.invantive.com' changed to 'download.invantive.eu'"
    @($Task.Logs.Where({ $_ -like '*source identity*' })).Count | Should -Be 1
  }

  It 'preserves all trusted sources when reporting a new source' {
    $Task = New-CheckTestTask -Name MultipleSources `
      -LastInstallerUrl 'https://download.example.com/setup.exe' `
      -CurrentInstallerUrl 'https://new.example.com/setup.exe'
    $Task.LastState.Installer += [ordered]@{ InstallerUrl = 'https://cdn.example.com/setup.exe' }

    $null = $Task.Check()

    $Task.Logs | Should -Contain "⚠️ [Installer #1/1] The installer source identities 'download.example.com', 'cdn.example.com' changed to 'new.example.com'"
  }

  It 'marks error logs with a cross mark and leaves info logs unmarked' {
    $Task = New-CheckTestTask -Name LogMarkers `
      -LastInstallerUrl 'https://github.com/example/repo/releases/download/v1/app.exe' `
      -CurrentInstallerUrl 'https://github.com/example/repo/releases/download/v2/app.exe'

    $Task.Log('Something went wrong', 'Error')
    $Task.Log('Just a note', 'Info')

    $Task.Logs[0] | Should -Be '❌ Something went wrong'
    $Task.Logs[1] | Should -Be 'Just a note'
  }

  It 'does not warn when the URL changes within the same source identity' {
    $Task = New-CheckTestTask -Name SameIdentity `
      -LastInstallerUrl 'https://github.com/example/repo/releases/download/v1/app.exe' `
      -CurrentInstallerUrl 'https://github.com/example/repo/releases/download/v2/app.exe'

    $null = $Task.Check()

    $Task.Logs -join "`n" | Should -Not -Match 'source identity'
  }

  It 'does not warn when GitLab generic package versions change within one project' {
    $Task = New-CheckTestTask -Name GitLabPackage `
      -LastInstallerUrl 'https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/16.0.0/windows_10_cmake_Release_graphviz-install-16.0.0-win32.exe' `
      -CurrentInstallerUrl 'https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/16.1.0/windows_10_cmake_Release_graphviz-install-16.1.0-win32.exe'
    $Task.LastState.Installer += [ordered]@{ InstallerUrl = 'https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/16.0.0/windows_10_cmake_Release_graphviz-install-16.0.0-win64.exe' }
    $Task.CurrentState.Installer += [ordered]@{ InstallerUrl = 'https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/16.1.0/windows_10_cmake_Release_graphviz-install-16.1.0-win64.exe' }

    $null = $Task.Check()

    $Task.Logs -join "`n" | Should -Not -Match 'source identity'
  }

  It 'does not warn for a new task' {
    $TaskPath = Join-Path $TestDrive 'NewTask'
    $null = New-Item -Path $TaskPath -ItemType Directory -Force
    Set-Content -LiteralPath (Join-Path $TaskPath 'Script.ps1') -Value ''
    $Task = [PackageTask]::new([ordered]@{ Name = 'NewTask'; Path = $TaskPath; Config = [ordered]@{} })
    $Task.CurrentState.Version = '2.0.0'
    $Task.CurrentState.Installer += [ordered]@{ InstallerUrl = 'https://github.com/example/repo/releases/download/v2/app.exe' }

    $null = $Task.Check()

    $Task.Logs -join "`n" | Should -Not -Match 'source identity'
  }

  It 'does not warn when the task checks versions only' {
    $Task = New-CheckTestTask -Name VersionOnly `
      -LastInstallerUrl 'https://github.com/example/old/releases/download/v1/app.exe' `
      -CurrentInstallerUrl 'https://github.com/example/new/releases/download/v2/app.exe' `
      -Config ([ordered]@{ CheckVersionOnly = $true })

    $null = $Task.Check()

    $Task.Logs -join "`n" | Should -Not -Match 'source identity'
  }
}

AfterAll {
  Remove-Item -Path 'Function:\Write-Log' -Force -ErrorAction Ignore
  Remove-Item -Path 'Function:\Send-WinGetManifest' -Force -ErrorAction Ignore
  Remove-Variable -Name SubmissionTestCalls, SubmissionTestSkipInstallerAnalysis, SubmissionTestShouldFail -Scope Global -ErrorAction Ignore
}
