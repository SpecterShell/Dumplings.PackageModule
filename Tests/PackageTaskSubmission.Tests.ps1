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

AfterAll {
  Remove-Item -Path 'Function:\Write-Log' -Force -ErrorAction Ignore
  Remove-Item -Path 'Function:\Send-WinGetManifest' -Force -ErrorAction Ignore
  Remove-Variable -Name SubmissionTestCalls, SubmissionTestShouldFail -Scope Global -ErrorAction Ignore
}
