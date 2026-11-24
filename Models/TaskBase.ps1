# SPDX-License-Identifier: Apache-2.0

enum LogLevel {
  Verbose
  Log
  Info
  Warning
  Error
}

class DumplingsTaskBase: System.IDisposable {
  #region Properties
  [ValidateNotNullOrEmpty()][string]$Name
  [ValidateNotNullOrEmpty()][string]$Path
  [System.Collections.IDictionary]$Config = [ordered]@{}
  [string]$ScriptPath
  [bool]$InvocationSucceeded = $false
  [bool]$InvocationSkipped = $false
  #endregion

  DumplingsTaskBase([System.Collections.IDictionary]$Properties) {
    # Load name
    if (-not $Properties.Contains('Name') -or [string]::IsNullOrEmpty($Properties.Name)) { throw 'DumplingsTaskBase: The provided task name is null or empty' }
    $this.Name = $Properties.Name

    # Load path
    if (-not $Properties.Contains('Path') -or [string]::IsNullOrEmpty($Properties.Path)) { throw 'DumplingsTaskBase: The provided task path is null or empty' }
    if (-not (Test-Path -Path $Properties.Path)) { throw 'DumplingsTaskBase: The provided task path is not reachable' }
    $this.Path = $Properties.Path

    # Load config
    if ($Properties.Contains('Config')) {
      if ($Properties.Config -and $Properties.Config -is [System.Collections.IDictionary]) {
        $this.Config = $Properties.Config
      } else {
        throw 'DumplingsTaskBase: The provided task config is empty or not a valid dictionary'
      }
    } else {
      $Private:ConfigPath = Join-Path $this.Path 'Config.yaml'
      if (Test-Path -Path $Private:ConfigPath) {
        try {
          $RawConfig = Get-Content -Path $Private:ConfigPath -Raw | ConvertFrom-Yaml -Ordered
          if ($RawConfig -and $RawConfig -is [System.Collections.IDictionary]) {
            $this.Config = $RawConfig
          } else {
            Write-Log -Object 'The config file is invalid. Assigning an empty hashtable' -Level Warning
          }
        } catch {
          Write-Log -Object "Failed to load config. Assigning an empty hashtable: ${_}" -Level Warning
        }
      }
    }

    # Probe script
    $this.ScriptPath = Join-Path $this.Path 'Script.ps1'
    if (-not (Test-Path -Path $this.ScriptPath)) { throw 'DumplingsTaskBase: The script file is not found' }
  }

  [void] Dispose() {}

  # Log in specified level
  [void] Log([string]$Message, [LogLevel]$Level) {
    Write-Log -Object $Message -Level $Level
  }

  # Log in default level
  [void] Log([string]$Message) {
    $this.Log($Message, 'Log')
  }

  # Invoke script
  [void] Invoke() {
    $this.InvocationSucceeded = $false
    $this.InvocationSkipped = $false
    if ((($Global:DumplingsPreference.Contains('Force') -and $Global:DumplingsPreference.Force) -or ($Global:DumplingsPreference.Contains('NoSkip') -and $Global:DumplingsPreference.NoSkip)) -or -not ($this.Config.Contains('Skip') -and $this.Config.Skip)) {
      Write-Log -Object 'Run!'
      try {
        $null = & $this.ScriptPath
        $this.InvocationSucceeded = $true
      } catch {
        $_ | Out-Host
        $this.Log("Unexpected error: ${_}", 'Error')
      }
    } else {
      $this.InvocationSkipped = $true
      $this.Log('Skipped', 'Info')
    }
  }
}
