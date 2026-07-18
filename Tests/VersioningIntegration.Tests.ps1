BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Index.ps1') -Force

  function global:Write-Log {
    param ($Object, $Level)
    $null = $Object, $Level
  }
}

Describe 'PackageTask chunk version state comparison' {
  It 'classifies <LastVersion> to <CurrentVersion> as <ExpectedStatus>' -ForEach @(
    @{ LastVersion = '10rc2'; CurrentVersion = '10'; ExpectedStatus = 'Updated' }
    @{ LastVersion = '1.2.3-alpha'; CurrentVersion = '1.2.3'; ExpectedStatus = 'Updated' }
    @{ LastVersion = '1.2.3'; CurrentVersion = '1.2.3+1'; ExpectedStatus = 'Updated' }
    @{ LastVersion = '1.2.3-0.0.0'; CurrentVersion = '1.2.3'; ExpectedStatus = '' }
    @{ LastVersion = '1.2.3+2'; CurrentVersion = '1.2.3+1'; ExpectedStatus = 'Rollbacked' }
    @{ LastVersion = '6.8.7_130258'; CurrentVersion = '6.8.7.1_130597'; ExpectedStatus = 'Updated' }
  ) {
    $TaskPath = Join-Path $TestDrive ([guid]::NewGuid().ToString())
    $null = New-Item -Path $TaskPath -ItemType Directory
    Set-Content -LiteralPath (Join-Path $TaskPath 'Script.ps1') -Value ''
    Set-Content -LiteralPath (Join-Path $TaskPath 'State.yaml') -Value "Version: ${LastVersion}"

    $Task = [PackageTask]::new([ordered]@{
        Name   = 'VersionTest'
        Path   = $TaskPath
        Config = [ordered]@{ CheckVersionOnly = $true }
      })
    $Task.CurrentState = [ordered]@{ Version = $CurrentVersion }
    $Global:DumplingsPreference = [ordered]@{}

    $Task.Check() | Should -Be $ExpectedStatus
  }
}

AfterAll {
  Remove-Item -Path 'Function:\Write-Log' -Force -ErrorAction Ignore
}
