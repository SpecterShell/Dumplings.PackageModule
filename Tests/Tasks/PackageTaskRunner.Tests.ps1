BeforeAll {
  $PackageIndex = (Resolve-Path (Join-Path $PSScriptRoot '..\..\Index.ps1')).Path
  $CoreIndex = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\Core\Index.ps1'))
}

Describe 'PackageTask integration with explicit worker contexts' -Tag Unit {
  It 'runs real models in four isolated worker runspaces without side effects' {
    if (-not (Test-Path $CoreIndex)) { Set-ItResult -Skipped -Because 'The sibling Core checkout is unavailable'; return }
    $Root = New-Item (Join-Path $TestDrive 'runner') -ItemType Directory
    $ModuleRoot = New-Item (Join-Path $Root 'Modules\Probe') -ItemType Directory -Force
    Set-Content (Join-Path $ModuleRoot 'Index.ps1') ('. ''' + $PackageIndex.Replace("'", "''") + "'")
    Set-Content (Join-Path $Root 'Preference.yaml') "Timeout: 60`nEnableMessage: false`nEnableSubmit: false`nEnableWrite: false"
    foreach ($Name in '#Provider', 'One', 'Two', 'Three') {
      $TaskRoot = New-Item (Join-Path $Root 'Tasks' $Name) -ItemType Directory -Force
      $Config = if ($Name -eq '#Provider') { 'Type: SimpleTask' } else { "Type: PackageTask`nWinGetIdentifier: Example.$Name`nDependsOn: ['#Provider']" }
      Set-Content (Join-Path $TaskRoot 'Config.yaml') $Config
      $Script = if ($Name -eq '#Provider') { '$Global:DumplingsStorage["FixtureVersion"] = "1.2.3"' } else { '$this.CurrentState.Version = $Global:DumplingsStorage["FixtureVersion"]' }
      Set-Content (Join-Path $TaskRoot 'Script.ps1') $Script
    }
    $Command = "Set-Location '$($Root.FullName.Replace("'", "''"))'; & '$($CoreIndex.Replace("'", "''"))' -ThrottleLimit 4 -PassThru -MeasurePerformance | Select-Object Name, InvocationSucceeded, CurrentState | ConvertTo-Json -Depth 5 | Set-Content result.json"
    & pwsh -NoProfile -NonInteractive -InputFormat Text -OutputFormat Text -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))) *> (Join-Path $Root 'run.log')
    $LASTEXITCODE | Should -Be 0 -Because (Get-Content (Join-Path $Root 'run.log') -Raw)
    $Tasks = @(Get-Content (Join-Path $Root 'result.json') -Raw | ConvertFrom-Json)
    $Tasks.Count | Should -Be 4
    @($Tasks | Where-Object { -not $_.InvocationSucceeded }).Count | Should -Be 0
    @($Tasks | Where-Object Name -NE '#Provider' | ForEach-Object { $_.CurrentState.Version } | Select-Object -Unique) | Should -Be @('1.2.3')
    @(Get-ChildItem (Join-Path $Root 'Tasks') -Recurse -Filter State.yaml).Count | Should -Be 0
  }
}
