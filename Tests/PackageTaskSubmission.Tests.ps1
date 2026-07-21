BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Index.ps1') -Force

  function global:Write-Log {
    param ($Object, $Level)
    $null = $Object, $Level
  }

  function global:Send-WinGetManifest {
    param ($Task)
    if ($Global:SubmissionTestShouldFail) { throw 'synthetic submission failure' }
    $Global:SubmissionTestCalls.Add($Task.Name)
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

Describe 'PackageTask WinGet submission claims' {
  BeforeEach {
    $Global:DumplingsPreference = [ordered]@{ EnableSubmit = $true }
    $Global:DumplingsStorage = [hashtable]::Synchronized(@{})
    $Global:DumplingsStorage['__DumplingsWinGetSubmissionClaims'] =
    [Collections.Concurrent.ConcurrentDictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Global:SubmissionTestCalls = [Collections.Generic.List[string]]::new()
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
}

Describe 'PackageTask Check domain-change warning' {
  BeforeEach {
    $Global:DumplingsPreference = [ordered]@{}
  }

  It 'warns when the installer source identity changes' {
    $Task = New-CheckTestTask -Name DomainChange `
      -LastInstallerUrl 'https://github.com/example/old/releases/download/v1/app.exe' `
      -CurrentInstallerUrl 'https://github.com/example/new/releases/download/v2/app.exe'

    $null = $Task.Check()

    $Task.Logs -join "`n" | Should -Match "⚠️ The installer source identity 'github\.com/example/new' changed from the trusted history"
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
  Remove-Variable -Name SubmissionTestCalls, SubmissionTestShouldFail -Scope Global -ErrorAction Ignore
}
