# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

function Test-WinGetManifest {
  <#
  .SYNOPSIS
    Test the WinGet manifest
  .DESCRIPTION
    Test the WinGet manifest by validating it using the WinGet client.
  .PARAMETER Path
    The path to the new manifests to be validated.
  #>
  param (
    [Parameter(Mandatory, Position = 0, HelpMessage = 'The path to the new manifests to be validated')]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )

  $WinGetOutput = ''
  $WinGetMaximumRetryCount = 3
  for ($i = 0; $i -lt $WinGetMaximumRetryCount; $i++) {
    try {
      winget.exe validate $Path | Out-String -Stream -OutVariable 'WinGetOutput'
      break
    } catch {
      if ($_.FullyQualifiedErrorId -eq 'CommandNotFoundException') {
        throw 'Failed to validate manifests: Could not locate WinGet client for validating manifests. Is it installed and added to PATH?'
      } elseif ($_.FullyQualifiedErrorId -eq 'ProgramExitedWithNonZeroCode') {
        # WinGet may throw warnings for, for example, not specifying the installer switches for EXE installers. Such warnings are ignored
        if ($_.Exception.ExitCode -eq -1978335192) {
          break
        } else {
          # WinGet may crash when multiple instances are initiated simultaneously. Retry the validation for a few times
          if ($i -eq $WinGetMaximumRetryCount - 1) {
            throw "Failed to pass manifests validation: $($WinGetOutput -join "`n")"
          } else {
            $Task.Log("WinGet exits with exitcode $($_.Exception.ExitCode)", 'Warning')
          }
        }
      } else {
        $Task.Log("Failed to validate manifests: ${_}", 'Error')
        throw $_
      }
    }
  }
}

function Send-WinGetManifest {
  <#
  .SYNOPSIS
    Generate and submit WinGet package manifests
  .DESCRIPTION
    Generate WinGet package manifests, upload them to the origin repo and create a pull request in the upstream repo
    Specifically, it does the following:
    1. Check existing pull requests in upstream.
    2. Generate new manifests using the information from current state.
    3. Validate new manifests.
    4. Upload new manifests to origin.
    5. Create pull requests in upstream.
  .PARAMETER Task
    The task object to be handled
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The task object to be handled')]
    $Task
  )

  #region Parameters for repo
  # Parameters for repo
  $UpstreamRepoOwner = $Global:DumplingsPreference['WinGetUpstreamRepoOwner'] ?? 'microsoft'
  $UpstreamRepoName = $Global:DumplingsPreference['WinGetUpstreamRepoName'] ?? 'winget-pkgs'
  $UpstreamRepoBranch = $Global:DumplingsPreference['WinGetUpstreamRepoBranch'] ?? 'master'

  if ($Global:DumplingsPreference['WinGetOriginRepoOwner']) {
    $OriginRepoOwner = $Global:DumplingsPreference.WinGetOriginRepoOwner
  } elseif (Test-Path -Path 'Env:\GITHUB_ACTIONS') {
    $OriginRepoOwner = $Env:GITHUB_REPOSITORY_OWNER
  } else {
    throw 'The WinGet origin repo owner is unset'
  }
  $OriginRepoName = $Global:DumplingsPreference['WinGetOriginRepoName'] ?? 'winget-pkgs'
  $OriginRepoBranch = $Global:DumplingsPreference['WinGetOriginRepoBranch'] ?? 'master'
  #endregion

  #region Parameters for package
  [string]$PackageIdentifier = $Task.Config.WinGetIdentifier
  try {
    $null = Test-YamlObject -InputObject $PackageIdentifier -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageIdentifier -WarningAction Stop
  } catch {
    throw "The PackageIdentifier `"${PackageIdentifier}`" is invalid: ${_}"
  }

  [string]$PackageVersion = $Task.CurrentState.Contains('RealVersion') ? $Task.CurrentState.RealVersion : $Task.CurrentState.Version
  try {
    $null = Test-YamlObject -InputObject $PackageVersion -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageVersion -WarningAction Stop
  } catch {
    throw "The PackageVersion `"${PackageVersion}`" is invalid: ${_}"
  }

  $PackageLastVersion = Get-WinGetGitHubPackageVersion -PackageIdentifier $PackageIdentifier -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $OriginRepoBranch -RootPath 'manifests' | Select-Object -Last 1
  if (-not $PackageLastVersion) { throw "Could not find any version of the package ${PackageIdentifier}" }

  $NewManifestsPath = (New-Item -Path (Join-Path $Global:DumplingsOutput 'WinGet' $PackageIdentifier $PackageVersion) -ItemType Directory -Force).FullName
  #endregion

  #region Parameters for publishing
  $NewBranchName = "${PackageIdentifier}-${PackageVersion}-$(Get-Random)" -replace '[\~,\^,\:,\\,\?,\@\{,\*,\[,\s]{1,}|[.lock|/|\.]*$|^\.{1,}|\.\.', ''
  $NewCommitType = if ($Global:DumplingsPreference['NewCommitType']) {
    $Global:DumplingsPreference.NewCommitType
  } else {
    switch (([Versioning]$PackageVersion).CompareTo([Versioning]$PackageLastVersion)) {
      { $_ -gt 0 } { 'New version'; continue }
      0 { 'Update'; continue }
      { $_ -lt 0 } { 'Add version'; continue }
    }
  }
  $NewCommitName = "${NewCommitType}: ${PackageIdentifier} version ${PackageVersion}"
  if ($Task.CurrentState.Contains('RealVersion')) { $NewCommitName += " ($($Task.CurrentState.Version))" }
  #endregion

  #region Check existing pull requests in the upstream repo
  if ($Global:DumplingsPreference['Force']) {
    $Task.Log('Skip checking pull requests in the upstream repo in force mode', 'Info')
  } elseif ($Global:DumplingsPreference['Dry']) {
    $Task.Log('Skip checking pull requests in the upstream repo in dry mode', 'Info')
  } elseif ($Task.Config['IgnorePRCheck']) {
    $Task.Log('Skip checking pull requests in the upstream repo as the task is set to do so', 'Info')
  } elseif (-not $Task.Status.Contains('New') -and $Task.LastState.Contains('RealVersion') -and ($Task.LastState.Version -cne $Task.CurrentState.Version) -and ($Task.LastState.RealVersion -ceq $Task.CurrentState.RealVersion)) {
    $Task.Log('Checking existing pull requests in the upstream repo', 'Verbose')
    $OldPullRequests = Find-WinGetGitHubPullRequest -Query "$($PackageIdentifier.Replace('.', '/'))/$($Task.CurrentState.RealVersion) in:path" -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
    if ($OldPullRequestsItems = $OldPullRequests.items | Where-Object -FilterScript { $_.title -match "(\s|^)$([regex]::Escape($PackageIdentifier))(\s|$)" -and $_.title -match "(\s|^)$([regex]::Escape($Task.CurrentState.RealVersion))(\s|$)" -and $_.title -match "(\s|\(|^)$([regex]::Escape($Task.CurrentState.Version))(\s|\)|$)" }) {
      throw "Found existing pull requests:`n$($OldPullRequestsItems | Select-Object -First 3 | ForEach-Object -Process { "$($_.title) - $($_.html_url)" } | Join-String -Separator "`n")"
    }
  } else {
    $Task.Log('Checking existing pull requests in the upstream repo', 'Verbose')
    $OldPullRequests = Find-WinGetGitHubPullRequest -Query "$($PackageIdentifier.Replace('.', '/'))/${PackageVersion} in:path" -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
    if ($OldPullRequestsItems = $OldPullRequests.items | Where-Object -FilterScript { $_.title -match "(\s|^)$([regex]::Escape($PackageIdentifier))(\s|$)" -and $_.title -match "(\s|^)$([regex]::Escape($PackageVersion))(\s|$)" }) {
      throw "Found existing pull requests:`n$($OldPullRequestsItems | Select-Object -First 3 | ForEach-Object -Process { "$($_.title) - $($_.html_url)" } | Join-String -Separator "`n")"
    }
  }
  #endregion

  #region Generate manifests
  # Map the release date to the installer entries
  if ($Task.CurrentState['ReleaseTime']) {
    $ReleaseDate = $Task.CurrentState.ReleaseTime -is [datetime] -or $Task.CurrentState.ReleaseTime -is [System.DateTimeOffset] ? $Task.CurrentState.ReleaseTime.ToUniversalTime().ToString('yyyy-MM-dd') : ($Task.CurrentState.ReleaseTime | Get-Date -Format 'yyyy-MM-dd')
    $Task.CurrentState.Installer | ForEach-Object -Process { if (-not $_.Contains('ReleaseDate')) { $_.ReleaseDate = $ReleaseDate } }
  }

  # Read the old manifests
  $OldManifests = Read-WinGetGitHubManifests -PackageIdentifier $PackageIdentifier -PackageVersion $PackageLastVersion -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $OriginRepoBranch -RootPath 'manifests' | Convert-WinGetManifestsFromYaml
  # If the old manifests exist, make sure to use the same casing as the existing package identifier
  $PackageIdentifier = $OldManifests.Version.PackageIdentifier
  # Update the manifests
  $NewManifests = Update-WinGetManifests -PackageVersion $PackageVersion -VersionManifest $OldManifests.Version -InstallerManifest $OldManifests.Installer -LocaleManifests $OldManifests.Locale -InstallerEntries $Task.CurrentState.Installer -LocaleEntries $Task.CurrentState.Locale -InstallerFiles $Task.InstallerFiles -ReplaceInstallers:$Task.Config['WinGetReplaceMode'] | Convert-WinGetManifestsToYaml
  #endregion

  # Validate manifests using WinGet client
  $null = $NewManifests | Add-WinGetLocalManifests -PackageIdentifier $PackageIdentifier -Path $NewManifestsPath
  Test-WinGetManifest -Path $NewManifestsPath

  # Do not upload manifests in dry mode
  if ($Global:DumplingsPreference['Dry']) {
    $Task.Log('Running in dry mode. Exiting...', 'Info')
    return
  }

  # Create a new branch in the origin repo
  # The new branch is based on the default branch of the origin repo instead of the one of the upstream repo
  # This is to mitigate the occasional and weird issue of "ref not found" when creating a branch based on the upstream default branch
  # The origin repo should be synced as early as possible to avoid conflicts with other commits
  $NewBranch = New-WinGetGitHubBranch -Name $NewBranchName -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $OriginRepoBranch

  # Upload new manifests
  $NewCommitSha = Add-WinGetGitHubManifests -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $NewBranchName -RepoSha $NewBranch.object.sha -RootPath 'manifests' -Manifest $NewManifests -CommitMessage $NewCommitName

  #region Remove old manifests
  # Remove old manifests, if
  # 1. The task is configured to remove the last version, or
  # 2. No installer URL is changed compared with the last state while the version is updated
  $RemoveLastVersionReason = $null
  if ($Task.Config.Contains('RemoveLastVersion')) {
    if ($Task.Config.RemoveLastVersion) {
      $RemoveLastVersionReason = 'This task is configured to remove the last version'
    }
  } elseif (-not $Task.Status.Contains('New') -and ($Task.LastState.Version -cne $Task.CurrentState.Version) -and -not (Compare-Object -ReferenceObject $Task.LastState -DifferenceObject $Task.CurrentState -Property { $_.Installer.InstallerUrl })) {
    $RemoveLastVersionReason = 'No installer URL is changed compared with the last state while the version is updated'
  }
  if ($RemoveLastVersionReason) {
    if ($PackageLastVersion -cne $PackageVersion) {
      $Task.Log("Removing the manifests of the last version ${PackageLastVersion}: ${RemoveLastVersionReason}", 'Info')
      $CommitMessage = "Remove version: ${PackageIdentifier} version ${PackageLastVersion}"
      $NewCommitSha = Remove-WinGetGitHubManifests -PackageIdentifier $PackageIdentifier -PackageVersion $PackageLastVersion -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $NewBranchName -RepoSha $NewCommitSha -RootPath 'manifests' -CommitMessage $CommitMessage
    } else {
      $Task.Log("Overriding the manifests of the last version ${PackageLastVersion}: ${RemoveLastVersionReason}", 'Info')
    }
  }
  #endregion

  # Create a pull request in the upstream repo
  $NewPullRequestBody = (Test-Path -Path 'Env:\GITHUB_ACTIONS') ? `
    "Automated by [🥟 ${Env:GITHUB_REPOSITORY_OWNER}/Dumplings](https://github.com/${Env:GITHUB_REPOSITORY_OWNER}/Dumplings) in workflow run [#${Env:GITHUB_RUN_NUMBER}](https://github.com/${Env:GITHUB_REPOSITORY_OWNER}/Dumplings/actions/runs/${Env:GITHUB_RUN_ID})." : `
    "Created by [🥟 Dumplings](https://github.com/${OriginRepoOwner}/Dumplings)."
  $NewPullRequest = New-WinGetGitHubPullRequest -Title $NewCommitName -Body $NewPullRequestBody -Head "${OriginRepoOwner}:${NewBranchName}" -Base $UpstreamRepoBranch -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
  $Task.Log("Pull request created: $($NewPullRequest.title) - $($NewPullRequest.html_url)", 'Info')
}

Export-ModuleMember -Function '*'
