<#
.SYNOPSIS
  A model with the minimum logic necessary to run a script
.DESCRIPTION
  This model provides necessary interfaces for bootstrapping script and common method for task scripts.
  Generally it does the following:
  1. Implement a constructor and a method Invoke() to be called by the bootstrapping script:
     The constructor receives the properties and probes the script.
     The Invoke() method runs the script file ("Script.ps1") in the same folder as the task config file ("Config.yaml").
  2. Implement common method to be called by the task scripts including Log():
     - Log() prints the message to the console. If messaging is enabled, it will also be sent to Telegram.
.PARAMETER NoSkip
  Force run the script even if the task is set not to run
#>

enum LogLevel {
  Verbose
  Log
  Info
  Warning
  Error
}

class SimpleTask: System.IDisposable {
  #region Properties
  [ValidateNotNullOrEmpty()][string]$Name
  [ValidateNotNullOrEmpty()][string]$Path
  [System.Collections.IDictionary]$Config = [ordered]@{}
  [string]$ScriptPath
  #endregion

  SimpleTask([System.Collections.IDictionary]$Properties) {
    # Load name
    if (-not $Properties.Contains('Name') -or [string]::IsNullOrEmpty($Properties.Name)) { throw 'SimpleTask: The provided task name is null or empty' }
    $this.Name = $Properties.Name

    # Load path
    if (-not $Properties.Contains('Path') -or [string]::IsNullOrEmpty($Properties.Path)) { throw 'SimpleTask: The provided task path is null or empty' }
    if (-not (Test-Path -Path $Properties.Path)) { throw 'SimpleTask: The provided task path is not reachable' }
    $this.Path = $Properties.Path

    # Load config
    if ($Properties.Contains('Config')) {
      if ($Properties.Config -and $Properties.Config -is [System.Collections.IDictionary]) {
        $this.Config = $Properties.Config
      } else {
        throw 'SimpleTask: The provided task config is empty or not a valid dictionary'
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
    if (-not (Test-Path -Path $this.ScriptPath)) { throw 'SimpleTask: The script file is not found' }
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
    $DumplingsLogIdentifier = $Script:DumplingsLogIdentifier + $this.Name
    if (($Global:DumplingsPreference.Contains('NoSkip') -and $Global:DumplingsPreference.NoSkip) -or -not ($this.Config.Contains('Skip') -and $this.Config.Skip)) {
      Write-Log -Object 'Run!'
      try {
        $null = & $this.ScriptPath
      } catch {
        $_ | Out-Host
        $this.Log("Unexpected error: ${_}", 'Error')
      }
    } else {
      $this.Log('Skipped', 'Info')
    }
  }
}
