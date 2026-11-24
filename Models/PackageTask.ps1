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
.PARAMETER SkipInstallerAnalysis
  Skip static installer parsing and family detection while generating submitted manifests. This can be set globally or in a task Config.yaml
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

class PackageTask : DumplingsTaskBase {
  #region Properties
  [System.Collections.IDictionary]$LastState = [ordered]@{ Version = $null; Installer = @(); Locale = @() }
  [System.Collections.IDictionary]$CurrentState = [ordered]@{ Version = $null; Installer = @(); Locale = @() }
  [System.Collections.Generic.List[string]]$Status = [System.Collections.Generic.List[string]]@()
  [System.Collections.Generic.List[string]]$Logs = [System.Collections.Generic.List[string]]@()
  [System.Collections.IDictionary]$InstallerFiles = [ordered]@{}
  [System.Collections.IDictionary]$InstallerFileEvidence = [ordered]@{}
  hidden [Collections.Generic.HashSet[string]]$BorrowedTrackingFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  hidden [Collections.Generic.HashSet[string]]$OwnedTrackingFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  hidden [object]$PendingInstallerUpdate
  [bool]$MessageEnabled = $false
  [System.Collections.Generic.List[System.Tuple[string, Int64]]]$MessageSession = @()
  [long]$MessageSessionGeneration = 0
  hidden [string]$LastQueuedMessage
  hidden [string]$LastQueuedSessionKey
  hidden [object]$LastQueuedTicket
  #endregion

  PackageTask([Collections.IDictionary]$Properties) : base($Properties) { $this.InitializeState() }
  PackageTask([string]$Name, [string]$Path) : base(@{ Name = $Name; Path = $Path }) { $this.InitializeState() }
  PackageTask([string]$Name, [string]$Path, [Collections.IDictionary]$Config) : base(@{ Name = $Name; Path = $Path; Config = $Config }) { $this.InitializeState() }

  hidden [void] InitializeState() {
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

    # Preserve the configured note as the first package log entry.
    if ($this.Config.Contains('Notes')) { $this.Logs.Add($this.Config.Notes) }
  }

  [void] Dispose() {
    foreach ($InstallerPath in @(@($this.InstallerFiles.Values) + @($this.OwnedTrackingFiles) | Select-Object -Unique)) {
      if (-not $this.BorrowedTrackingFiles.Contains($InstallerPath) -and (Test-Path -LiteralPath $InstallerPath)) { Remove-Item -LiteralPath $InstallerPath -Force -ErrorAction 'Continue' }
    }
  }

  # Probe/hash/version work is separate from publishing, leaving a narrow place
  # for package-specific release metadata before completion. Logging during the
  # check must not activate previously enabled notification callbacks.
  [object] CheckInstallerUpdates([Collections.IDictionary]$Options) {
    if ($this.PendingInstallerUpdate -and -not $this.PendingInstallerUpdate.Completed) { throw 'Complete the pending installer update before checking again.' }
    $PreviousMessaging = $this.MessageEnabled
    $this.MessageEnabled = $false
    try {
      $Result = Get-PackageTaskInstallerUpdate -Task $this -Options $Options -Force:([bool]$Global:DumplingsPreference['Force'])
      foreach ($Warning in $Result.Warnings) { $this.Log($Warning, 'Warning') }
      if ($Result.Accepted) {
        foreach ($Path in $this.InstallerFiles.Values) { if (-not $this.OwnedTrackingFiles.Contains([string]$Path)) { $null = $this.BorrowedTrackingFiles.Add([string]$Path) } }
        foreach ($Path in $Result.OwnedFiles) { $null = $this.OwnedTrackingFiles.Add($Path) }
        foreach ($Url in $Result.Files.Keys) {
          $Path = [string]$Result.Files[$Url]
          $this.InstallerFiles[$Url] = $Path
          if ($Path -notin $Result.OwnedFiles) { $null = $this.BorrowedTrackingFiles.Add($Path) }
          else { $null = $this.BorrowedTrackingFiles.Remove($Path) }
        }
        foreach ($Path in $Result.FileEvidence.Keys) { $this.InstallerFileEvidence[$Path] = $Result.FileEvidence[$Path] }
        $this.CurrentState = $Result.CandidateState
        if ($Result.NeedsMetadata) { $null = $this.Check() }
        if ($Result.Outcome -eq 'Rebuilt' -and -not $this.Status.Contains('Rebuilt')) { $this.Status.Add('Rebuilt') }
      }
      $this.Log("Installer tracking: $($Result.Outcome)", 'Info')
      $this.PendingInstallerUpdate = $Result
      return $Result
    } finally { $this.MessageEnabled = $PreviousMessaging }
  }

  # Mark completion before external effects. Retrying a partly failed submission
  # must be an explicit new operation, not a duplicate completion of this ticket.
  [void] CompleteInstallerUpdates([object]$Result) {
    if (-not [object]::ReferenceEquals($this.PendingInstallerUpdate, $Result) -or $null -eq $Result) { throw 'Installer update result belongs to another task or check.' }
    if ($Result.Completed) { return }
    $Result.Completed = $true
    if (-not $Result.Accepted) { return }
    if ($Result.NeedsMetadata) { $this.Print() }
    if ($Result.ShouldWrite) { $this.Write() }
    if ($Result.ShouldMessage) { $this.Message() }
    if ($Result.ShouldSubmit) { $this.Submit() }
  }

  # Log in specified level
  [void] Log([string]$Message, [LogLevel]$Level) {
    Write-Log -Object $Message -Level $Level
    if ($Level -ne 'Verbose') {
      # Messaging has no colored text, so mark warnings and errors with emoji
      # to make them stand out in the log section of outgoing messages
      $Prefix = $Level -eq 'Error' ? '❌ ' : ($Level -eq 'Warning' ? '⚠️ ' : '')
      $this.Logs.Add("${Prefix}${Message}")
      if ($this.MessageEnabled) { $this.Message() }
    }
  }

  # Log in default level
  [void] Log([string]$Message) {
    $this.Log($Message, 'Log')
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
        switch (([ChunkVersion]$this.CurrentState.Version).CompareTo([ChunkVersion]$this.LastState.Version)) {
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

      # Warn when an installer URL moves to a different source identity (e.g., a
      # different repository, bucket, or host) compared with the last state. A
      # changed URL within the same identity, such as a new release asset path in
      # the same repository, is expected and does not warn.
      if (-not $this.Status.Contains('New') -and (-not $this.Config.Contains('CheckVersionOnly') -or -not $this.Config.CheckVersionOnly)) {
        $TrustedIdentities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($InstallerEntry in $this.LastState.Installer) {
          if ($null -eq $InstallerEntry -or [string]::IsNullOrWhiteSpace([string]$InstallerEntry['InstallerUrl'])) { continue }
          $Identity = Get-InstallerSourceIdentity -Uri $InstallerEntry['InstallerUrl']
          if (-not [string]::IsNullOrWhiteSpace($Identity)) { $null = $TrustedIdentities.Add($Identity) }
        }
        if ($TrustedIdentities.Count -gt 0) {
          $InstallerIndex = 0
          $PreviousIdentities = "'" + ($TrustedIdentities -join "', '") + "'"
          $IdentityLabel = $TrustedIdentities.Count -eq 1 ? 'identity' : 'identities'
          foreach ($InstallerEntry in $this.CurrentState.Installer) {
            $InstallerIndex += 1
            $Identity = Get-InstallerSourceIdentity -Uri $InstallerEntry['InstallerUrl']
            if (-not [string]::IsNullOrWhiteSpace($Identity) -and -not $TrustedIdentities.Contains($Identity)) {
              $this.Log("[Installer #${InstallerIndex}/$($this.CurrentState.Installer.Count)] The installer source ${IdentityLabel} ${PreviousIdentities} changed to '${Identity}'", 'Warning')
            }
          }
        }
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

  [string] ToMarkdown() { return ConvertTo-PackageTaskMessage -Task $this -Format Markdown }
  [string] ToTelegramMarkdown() { return ConvertTo-PackageTaskMessage -Task $this -Format Telegram }

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
        $Identifier = $this.GetMessageQueueIdentifier()
        $SessionKey = "PackageState:${Identifier}:$($this.MessageSessionGeneration)"
        $MessageText = $this.ToTelegramMarkdown()
        if ($this.LastQueuedSessionKey -ceq $SessionKey -and $this.LastQueuedMessage -ceq $MessageText -and $this.LastQueuedTicket -and $this.LastQueuedTicket.State -notin @('Failed', 'Cancelled', 'Superseded')) { return }
        $this.LastQueuedTicket = Send-QueuedTelegramMessage -Message $MessageText -AsMarkdown `
          -QueueKey $SessionKey -SessionKey $SessionKey
        $this.LastQueuedSessionKey = $SessionKey
        $this.LastQueuedMessage = $MessageText
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
        # Custom notifications remain independent FIFO entries unless a caller uses the queue API directly.
        $null = Send-QueuedTelegramMessage -Message $Message
      } catch {
        Write-Log -Object "Failed to send custom message: ${_}" -Level Error
        $this.Logs.Add($_.ToString())
      }
    }
  }

  [void] ResetMessage() {
    # Start a fresh queue-owned session while preserving already queued generations.
    $this.MessageSessionGeneration++
    $this.MessageSession = [System.Collections.Generic.List[System.Tuple[string, Int64]]]@()
  }

  [string] GetMessageQueueIdentifier() { return Get-PackageTaskIdentifier -Config $this.Config -Fallback $this.Name }

  # Generate manifests and upload them to the origin repository, and then create pull request in the upstream repository
  [void] Submit() {
    if ($Global:DumplingsPreference.Contains('EnableSubmit') -and $Global:DumplingsPreference.EnableSubmit) {
      #region WinGet
      if ($this.Config.Contains('WinGetPackageIdentifier') -or $this.Config.Contains('WinGetIdentifier')) {
        # Claim the effective destination identifier before repository or network work begins.
        # The concurrent dictionary is shared by all worker runspaces for this runner invocation.
        [string]$TargetIdentifier = Get-PackageTaskIdentifier -Config $this.Config
        if ([string]::IsNullOrWhiteSpace($TargetIdentifier)) {
          throw 'The effective WinGet submission identifier is null or empty'
        }
        $Claims = $Global:DumplingsStorage['__DumplingsWinGetSubmissionClaims']
        if ($Claims -isnot [System.Collections.Concurrent.ConcurrentDictionary[string, string]]) {
          throw 'The runner-wide WinGet submission claim registry is unavailable or invalid'
        }

        [string]$ExistingOwner = $null
        if (-not $Claims.TryAdd($TargetIdentifier, $this.Name)) {
          $null = $Claims.TryGetValue($TargetIdentifier, [ref]$ExistingOwner)
          if ($ExistingOwner -cne $this.Name) {
            $this.Log("Skipping WinGet submission for ${TargetIdentifier}; task '${ExistingOwner}' already owns the submission claim", 'Warning')
            return
          }
        }

        $this.Log('Submitting WinGet manifests', 'Info')
        [bool]$SkipInstallerAnalysis = [bool]($Global:DumplingsPreference['SkipInstallerAnalysis'] -or $this.Config['SkipInstallerAnalysis'])
        Send-WinGetManifest -Task $this -SkipInstallerAnalysis:$SkipInstallerAnalysis
      }
      #endregion
    }
  }
}
