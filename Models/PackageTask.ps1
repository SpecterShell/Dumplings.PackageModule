<#
.SYNOPSIS
  A model to check updates, send messages and submit manifests for WinGet packages
.DESCRIPTION
  This model provides necessary interfaces for bootstrapping script and common methods for task scripts to automate checking updates for WinGet packages.
  Specifially it does the following:
  1. Implement a constructor and a method Invoke() to be called by the bootstrapping script:
     The constructor receives the properties, probes the script, and loads the last state ("State.yaml", if existed) which contains the information stored during previous runs.
     The Invoke() method runs the script file ("Script.ps1") in the same folder as the task config file ("Config.yaml").
  2. Implement common methods to be called by the task scripts including Logging(), Write(), Message() and Submit(), Check():
     - Log() prints the message to the console. If messaging is enabled, it will also be sent to Telegram.
     - Write() writes current state to the files "State.yaml" and "Log*.yaml", where the former file will be read in the subsequent runs.
     - Print() prints current state to console
     - Message() enables sending current state to Telegram formatted with a built-in template.
       This method then will be invoked every time the Logging() method is invoked.
     - Submit() creates and submits the package to multiple repos
     - Check() compares the information obtained in current run (aka current state) with that obtained in previous runs (aka last state).
       The general rule is as follows:
       1. If last state is not present, the init method adds "New" to status and only Write() will be invoked.
       2. If last state is present and there is no difference in versions and installer URLs, the method adds nothing to status and nothing gonna happen.
       3. If last state is present and only the installer URLs are changed, the method adds "Chnaged" to status, and Write() and Message() will be invoked.
       4. If last state is present and the version is increased, the method adds "Updated" to status, and Write(), Message() and Submit() will be invoked.
       The rule for those set to check versions only is as follows:
       1. If last state is not present, the init method adds "New" to status and only Write() will be invoked.
       2. If last state is present and there is no difference in versions, the method adds nothing to status and nothing gonna happen.
       3. If last state is present and the version is increased, the method adds "Updated" to status, and Write(), Message() and Submit() will be invoked.
.PARAMETER NoSkip
  Force run the script even if the task is set not to run
.PARAMETER NoCheck
  Check() will always return 3 regardless of the difference between the states
.PARAMETER EnableWrite
  Allow Write() to write states to files
.PARAMETER EnableMessage
  Allow Message() to send states to Telegram
.PARAMETER EnableSubmit
  Allow Submit() to submit new manifests to upstream
.PARAMETER UpstreamOwner
  The owner of the upstream repository
.PARAMETER UpstreamRepo
  The name of the upstream repository
.PARAMETER UpstreamBranch
  The branch of the upstream repository
.PARAMETER OriginOwner
  The name of the origin repository
.PARAMETER OriginRepo
  The name of the origin repository
#>

enum LogLevel {
  Verbose
  Log
  Info
  Warning
  Error
}

class PackageTask: System.IDisposable {
  #region Properties
  [ValidateNotNullOrEmpty()][string]$Name
  [ValidateNotNullOrEmpty()][string]$Path
  [System.Collections.IDictionary]$Config = [ordered]@{}
  [System.Collections.IDictionary]$LastState = [ordered]@{ Version = $null; Installer = @(); Locale = @() }
  [System.Collections.IDictionary]$CurrentState = [ordered]@{ Version = $null; Installer = @(); Locale = @() }
  [ValidateNotNullOrEmpty()][string]$ScriptPath
  [System.Collections.Generic.List[string]]$Status = [System.Collections.Generic.List[string]]@()
  [System.Collections.Generic.List[string]]$Logs = [System.Collections.Generic.List[string]]@()
  [System.Collections.IDictionary]$InstallerFiles = [ordered]@{}
  [bool]$MessageEnabled = $false
  [System.Collections.Generic.List[System.Tuple[string, Int64]]]$MessageSession = @()
  #endregion

  # Initialize task
  PackageTask([System.Collections.IDictionary]$Properties) {
    # Load name
    if (-not $Properties.Contains('Name') -or [string]::IsNullOrEmpty($Properties.Name)) { throw 'PackageTask: The provided task name is null or empty' }
    $this.Name = $Properties.Name

    # Load path
    if (-not $Properties.Contains('Path') -or [string]::IsNullOrEmpty($Properties.Path)) { throw 'PackageTask: The provided task path is null or empty' }
    if (-not (Test-Path -Path $Properties.Path)) { throw 'PackageTask: The provided task path is not reachable' }
    $this.Path = $Properties.Path

    # Load config
    if ($Properties.Contains('Config')) {
      if ($Properties.Config -and $Properties.Config -is [System.Collections.IDictionary]) {
        $this.Config = $Properties.Config
      } else {
        throw 'PackageTask: The provided task config is empty or not a valid dictionary'
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

    # Load last state
    $Private:LastStatePath = Join-Path $this.Path 'State.yaml'
    if (Test-Path -Path $Private:LastStatePath) {
      try {
        $RawLastState = Get-Content -Path $Private:LastStatePath -Raw | ConvertFrom-Yaml -Ordered
        if ($RawLastState -and $RawLastState -is [System.Collections.IDictionary]) {
          $this.LastState = $RawLastState
        } else {
          Write-Log -Object 'The last state file is invalid. Assigning an empty hashtable' -Level Warning
        }
      } catch {
        Write-Log -Object "Failed to load last state. Assigning an empty hashtable: ${_}" -Level Warning
      }
    } else {
      $this.Status.Add('New')
    }

    # Probe script
    $this.ScriptPath = Join-Path $this.Path 'Script.ps1'
    if (-not (Test-Path -Path $this.ScriptPath)) { throw 'PackageTask: The script file is not found' }

    # Log notes
    if ($this.Config.Contains('Notes')) { $this.Logs.Add($this.Config.Notes) }
  }

  PackageTask([string]$Name, [string]$Path) {
    PackageTask(@{ Name = $Name; Path = $Path })
  }

  PackageTask([string]$Name, [string]$Path, [System.Collections.IDictionary]$Config) {
    PackageTask(@{ Name = $Name; Path = $Path; Config = $Config })
  }

  [void] Dispose() {
    foreach ($InstallerPath in $this.InstallerFiles.Values) {
      Remove-Item -Path $InstallerPath -Force -ErrorAction 'Continue'
    }
  }

  # Log in specified level
  [void] Log([string]$Message, [LogLevel]$Level) {
    Write-Log -Object $Message -Level $Level
    if ($Level -ne 'Verbose') {
      $this.Logs.Add($Message)
      if ($this.MessageEnabled) { $this.Message() }
    }
  }

  # Log in default level
  [void] Log([string]$Message) {
    $this.Log($Message, 'Log')
  }

  # Invoke script
  [void] Invoke() {
    $DumplingsLogIdentifier = $Script:DumplingsLogIdentifier + $this.Name
    if (($Global:DumplingsPreference.Contains('Force') -and $Global:DumplingsPreference.Force) -or -not ($this.Config.Contains('Skip') -and $this.Config.Skip)) {
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

  # Compare current state with last state
  [string] Check() {
    # Check whether the version property is present and valid
    if (-not $this.CurrentState.Contains('Version')) { throw 'The current state does not contain Version' }
    if ([string]::IsNullOrWhiteSpace($this.CurrentState.Version)) { throw 'The current state has an empty Version' }

    # Check whether the installer URL(s) is present and valid
    if (-not $this.Config.Contains('CheckVersionOnly') -or -not $this.Config.CheckVersionOnly) {
      foreach ($InstallerEntry in $this.CurrentState.Installer) {
        if (-not $InstallerEntry.Contains('InstallerUrl')) { throw 'One of the installer entries in the current state does not contain InstallerUrl' }
        if ([string]::IsNullOrWhiteSpace($InstallerEntry.InstallerUrl)) { throw 'One of the installer entries in the current state has an empty InstallerUrl' }
      }
    }

    if (-not $Global:DumplingsPreference.Contains('Force') -or -not $Global:DumplingsPreference.Force) {
      if (-not $this.Status.Contains('New')) {
        switch (([RawVersion]$this.CurrentState.Version).CompareTo([RawVersion]$this.LastState.Version)) {
          { $_ -gt 0 } {
            $this.Log("Updated: $($this.LastState.Version) → $($this.CurrentState.Version)", 'Info')
            $this.Status.Add('Updated')
            if (-not $this.Config.Contains('CheckVersionOnly') -or -not $this.Config.CheckVersionOnly) {
              if (Compare-Object -ReferenceObject $this.LastState -DifferenceObject $this.CurrentState -Property { $_.Installer.InstallerUrl }) {
                $this.Status.Add('Changed')
              }
            }
            continue
          }
          0 {
            if (-not $this.Config.Contains('CheckVersionOnly') -or -not $this.Config.CheckVersionOnly) {
              if (Compare-Object -ReferenceObject $this.LastState -DifferenceObject $this.CurrentState -Property { $_.Installer.InstallerUrl }) {
                $this.Log('Installer URLs changed', 'Info')
                $this.Status.Add('Changed')
              }
            }
            continue
          }
          { $_ -lt 0 } {
            $this.Log("Rollbacked: $($this.LastState.Version) → $($this.CurrentState.Version)", 'Warning')
            $this.Status.Add('Rollbacked')
            continue
          }
        }
      } else {
        # If this is a new task (no last state exists), skip the steps below
        $this.Log('New task', 'Info')
      }
    } else {
      $this.Log('Skip checking states', 'Info')
      $this.Status.AddRange([string[]]@('Changed', 'Updated'))
    }

    return ($this.Status -join '|')
  }

  # Write the state to a log file and a state file in YAML format
  [void] Write() {
    if ($Global:DumplingsPreference.Contains('EnableWrite') -and $Global:DumplingsPreference.EnableWrite) {
      # Writing current state to log file
      $LogName = "Log_$(Get-Date -AsUTC -Format "yyyyMMdd'T'HHmmss'Z'").yaml"
      $LogPath = Join-Path $this.Path $LogName
      Write-Log -Object "Writing current state to log file ${LogPath}"
      $this.CurrentState | ConvertTo-Yaml -OutFile $LogPath -Force

      # Writing current state to state file
      $StatePath = Join-Path $this.Path 'State.yaml'
      Write-Log -Object "Linking current state to the latest log file ${StatePath}"
      New-Item -Path $StatePath -ItemType SymbolicLink -Value $LogName -Force
    }
  }

  # Convert current state to Markdown message
  [string] ToMarkdown() {
    $Message = [System.Text.StringBuilder]::new(2048)

    # WinGetIdentifier
    if ($this.Config.Contains('WinGetIdentifier')) { $Message = $Message.AppendLine("**$($this.Config.WinGetIdentifier)**") }

    $Message = $Message.AppendLine()

    # Version
    $Message = $Message.AppendLine("**Version:** $($this.CurrentState['Version'] | ConvertTo-MarkdownEscapedText)")
    # RealVersion
    if ($this.CurrentState.Contains('RealVersion')) { $Message = $Message.AppendLine("**RealVersion:** $($this.CurrentState['RealVersion'] | ConvertTo-MarkdownEscapedText)") }

    # Installer
    for ($i = 0; $i -lt $this.CurrentState.Installer.Count; $i++) {
      $Installer = $this.CurrentState.Installer[$i]
      $Message = $Message.Append("**Installer \#$($i + 1)/$($this.CurrentState.Installer.Count) \(")
      if ($Installer.Contains('Query')) {
        if ($Installer.Query -is [scriptblock]) {
          $Message = $Message.Append('ScriptBlock')
        } elseif ($Installer.Query -is [System.Collections.IDictionary]) {
          $Message = $Message.Append(($Installer.Query.Contains('InstallerLocale') ? ($Installer.Query['InstallerLocale'] | ConvertTo-MarkdownEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('Architecture') ? ($Installer.Query['Architecture'] | ConvertTo-MarkdownEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('InstallerType') ? ($Installer.Query['InstallerType'] | ConvertTo-MarkdownEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('NestedInstallerType') ? ($Installer.Query['NestedInstallerType'] | ConvertTo-MarkdownEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('Scope') ? ($Installer.Query['Scope'] | ConvertTo-MarkdownEscapedText) : '\*'))
        } else {
          throw 'Invalid Query type'
        }
      } else {
        $Message = $Message.Append(($Installer.Contains('InstallerLocale') ? ($Installer['InstallerLocale'] | ConvertTo-MarkdownEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('Architecture') ? ($Installer['Architecture'] | ConvertTo-MarkdownEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('InstallerType') ? ($Installer['InstallerType'] | ConvertTo-MarkdownEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('NestedInstallerType') ? ($Installer['NestedInstallerType'] | ConvertTo-MarkdownEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('Scope') ? ($Installer['Scope'] | ConvertTo-MarkdownEscapedText) : '\*'))
      }
      $Message = $Message.AppendLine('\):**')
      $Message = $Message.AppendLine(($Installer['InstallerUrl'].Replace(' ', '%20') | ConvertTo-MarkdownEscapedText))
    }

    # ReleaseDate
    if ($this.CurrentState.Contains('ReleaseTime')) {
      if ($this.CurrentState.ReleaseTime -is [datetime]) {
        $Message = $Message.AppendLine("**ReleaseDate:** $($this.CurrentState.ReleaseTime.ToString('yyyy-MM-dd') | ConvertTo-MarkdownEscapedText)")
      } else {
        $Message = $Message.AppendLine("**ReleaseDate:** $($this.CurrentState.ReleaseTime | ConvertTo-MarkdownEscapedText)")
      }
    }

    # Locale
    foreach ($Entry in $this.CurrentState.Locale) {
      if ($Entry.Contains('Key') -and $Entry.Key -in @('ReleaseNotes', 'ReleaseNotesUrl')) {
        $Message = $Message.Append("**$($Entry['Key'] | ConvertTo-MarkdownEscapedText) \(")
        $Message = $Message.Append(($Entry.Contains('Locale') ? ($Entry['Locale'] | ConvertTo-MarkdownEscapedText) : '\*'))
        $Message = $Message.AppendLine('\):**')
        $Message = $Message.AppendLine(($Entry['Value'] | ConvertTo-MarkdownEscapedText))
      }
    }

    # Log
    if ($this.Logs.Count -gt 0) {
      $Message = $Message.AppendLine('**Log:**')
      foreach ($Log in $this.Logs) {
        $Message = $Message.AppendLine((($Log.Length -gt 1024 ? ($Log.SubString(0, 1024) + '...[truncated]') : $Log) | ConvertTo-MarkdownEscapedText))
      }
    }

    # Standard Markdown use two line endings as newline
    return $Message.ToString().Trim().ReplaceLineEndings("`n`n")
  }

  # Convert current state to Markdown message in Telegram standard
  [string] ToTelegramMarkdown() {
    $Message = [System.Text.StringBuilder]::new(2048)

    # WinGetIdentifier
    if ($this.Config.Contains('WinGetIdentifier')) { $Message = $Message.AppendLine("*$($this.Config.WinGetIdentifier | ConvertTo-TelegramEscapedText)*") }

    $Message = $Message.AppendLine()

    # Version
    $Message = $Message.AppendLine("*Version:* $($this.CurrentState['Version'] | ConvertTo-TelegramEscapedText)")
    # RealVersion
    if ($this.CurrentState.Contains('RealVersion')) { $Message = $Message.AppendLine("*RealVersion:* $($this.CurrentState['RealVersion'] | ConvertTo-TelegramEscapedText)") }

    # Installer
    for ($i = 0; $i -lt $this.CurrentState.Installer.Count -and $i -lt 10; $i++) {
      $Installer = $this.CurrentState.Installer[$i]
      $Message = $Message.Append("*Installer \#$($i + 1)/$($this.CurrentState.Installer.Count) \(")
      if ($Installer.Contains('Query')) {
        if ($Installer.Query -is [scriptblock]) {
          $Message = $Message.Append('ScriptBlock')
        } elseif ($Installer.Query -is [System.Collections.IDictionary]) {
          $Message = $Message.Append(($Installer.Query.Contains('InstallerLocale') ? ($Installer.Query['InstallerLocale'] | ConvertTo-TelegramEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('Architecture') ? ($Installer.Query['Architecture'] | ConvertTo-TelegramEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('InstallerType') ? ($Installer.Query['InstallerType'] | ConvertTo-TelegramEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('NestedInstallerType') ? ($Installer.Query['NestedInstallerType'] | ConvertTo-TelegramEscapedText) : '\*'))
          $Message = $Message.Append(', ')
          $Message = $Message.Append(($Installer.Query.Contains('Scope') ? ($Installer.Query['Scope'] | ConvertTo-TelegramEscapedText) : '\*'))
        } else {
          throw 'Invalid Query type'
        }
      } else {
        $Message = $Message.Append(($Installer.Contains('InstallerLocale') ? ($Installer['InstallerLocale'] | ConvertTo-TelegramEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('Architecture') ? ($Installer['Architecture'] | ConvertTo-TelegramEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('InstallerType') ? ($Installer['InstallerType'] | ConvertTo-TelegramEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('NestedInstallerType') ? ($Installer['NestedInstallerType'] | ConvertTo-TelegramEscapedText) : '\*'))
        $Message = $Message.Append(', ')
        $Message = $Message.Append(($Installer.Contains('Scope') ? ($Installer['Scope'] | ConvertTo-TelegramEscapedText) : '\*'))
      }
      $Message = $Message.AppendLine('\):*')
      $Message = $Message.AppendLine(($Installer['InstallerUrl'].Replace(' ', '%20') | ConvertTo-TelegramEscapedText))
    }

    # ReleaseTime
    if ($this.CurrentState.Contains('ReleaseTime')) {
      if ($this.CurrentState.ReleaseTime -is [datetime]) {
        $Message = $Message.AppendLine("*ReleaseDate:* $($this.CurrentState.ReleaseTime.ToString('yyyy-MM-dd') | ConvertTo-TelegramEscapedText)")
      } else {
        $Message = $Message.AppendLine("*ReleaseDate:* $($this.CurrentState.ReleaseTime | ConvertTo-TelegramEscapedText)")
      }
    }

    # Locale
    foreach ($Entry in $this.CurrentState.Locale) {
      if ($Entry.Contains('Key') -and $Entry.Key -in @('ReleaseNotes', 'ReleaseNotesUrl')) {
        $Message = $Message.Append("*$($Entry['Key'] | ConvertTo-TelegramEscapedText) \(")
        $Message = $Message.Append(($Entry.Contains('Locale') ? ($Entry['Locale'] | ConvertTo-TelegramEscapedText) : '\*'))
        $Message = $Message.AppendLine('\):*')
        $Message = $Message.AppendLine(($Entry['Value'] | ConvertTo-TelegramEscapedText))
      }
    }

    $Message = $Message.AppendLine()

    # Log
    if ($this.Logs.Count -gt 0) {
      $Message = $Message.AppendLine('*Log:*')
      foreach ($Log in $this.Logs) {
        $Message = $Message.AppendLine((($Log.Length -gt 1024 ? ($Log.SubString(0, 1024) + '...[truncated]') : $Log) | ConvertTo-TelegramEscapedText))
      }
    }

    return $Message.ToString().Trim()
  }

  # Print current state to console
  [void] Print() {
    $this.ToMarkdown() | Show-Markdown | Write-Log
  }

  # Send default message to Telegram
  [void] Message() {
    # Enable pushing new logs to Telegram once this method is called
    if (-not $this.MessageEnabled) { $this.MessageEnabled = $true }
    if ($Global:DumplingsPreference.Contains('EnableMessage') -and $Global:DumplingsPreference.EnableMessage) {
      try {
        $null = Send-TelegramMessage -Message $this.ToTelegramMarkdown() -AsMarkdown -Session $this.MessageSession
      } catch {
        Write-Log -Object "Failed to send default message: ${_}" -Level Error
        $this.Logs.Add($_.ToString())
      }
    }
  }

  # Send custom message to Telegram
  [void] Message([string]$Message) {
    if ($Global:DumplingsPreference.Contains('EnableMessage') -and $Global:DumplingsPreference.EnableMessage) {
      try {
        $null = Send-TelegramMessage -Message $Message
      } catch {
        Write-Log -Object "Failed to send custom message: ${_}" -Level Error
        $this.Logs.Add($_.ToString())
      }
    }
  }

  [void] ResetMessage() {
    $this.MessageSession = [System.Collections.Generic.List[System.Tuple[string, Int64]]]@()
  }

  # Generate manifests and upload them to the origin repository, and then create pull request in the upstream repository
  [void] Submit() {
    if ($Global:DumplingsPreference.Contains('EnableSubmit') -and $Global:DumplingsPreference.EnableSubmit) {
      #region WinGet
      if ($this.Config.Contains('WinGetIdentifier')) {
        $this.Log('Submitting WinGet manifests', 'Info')
        Send-WinGetManifest -Task $this
      }
      #endregion
    }
  }
}
