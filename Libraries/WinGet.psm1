# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

function Get-WinGetLocalRepoPath {
  <#
  .SYNOPSIS
    Get the location of local winget-pkgs repo
  .PARAMETER RepoName
    The name of the repo
  .PARAMETER RootPath
    The path to the folder containing the manifests
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, HelpMessage = 'The name of the repo')]
    [string]$RepoName = 'winget-pkgs',
    [Parameter(HelpMessage = 'The path to the folder containing the manifests')]
    [string]$RootPath
  )

  if ((Test-Path -Path 'Variable:\DumplingsPreference') -and -not [string]::IsNullOrWhiteSpace($Global:DumplingsPreference['LocalRepoPath']) -and (Test-Path -Path ($Path = Join-Path $Global:DumplingsPreference.LocalRepoPath $RootPath))) {
    return Resolve-Path -Path $Path
  } elseif ((Test-Path -Path 'Env:\GITHUB_WORKSPACE') -and (Test-Path -Path ($Path = Join-Path $Env:GITHUB_WORKSPACE $RepoName $RootPath))) {
    return Resolve-Path -Path $Path
  } elseif ((Test-Path -Path 'Variable:\DumplingsRoot') -and (Test-Path -Path ($Path = Join-Path $Global:DumplingsRoot '..' $RepoName $RootPath))) {
    return Resolve-Path -Path $Path
  } elseif (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' '..' '..' '..' $RepoName $RootPath)) {
    return Resolve-Path -Path $Path
  } else {
    return
  }
}

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

$GitHubTokenUsername = $null

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

  process {
    #region Parameters
    [string]$UpstreamRepoOwner = $Task.Config['WinGetUpstreamRepoOwner'] ?? $Global:DumplingsPreference['WinGetUpstreamRepoOwner'] ?? 'microsoft'
    [string]$UpstreamRepoName = $Task.Config['WinGetUpstreamRepoName'] ?? $Global:DumplingsPreference['WinGetUpstreamRepoName'] ?? 'winget-pkgs'
    [string]$UpstreamRepoBranch = $Task.Config['WinGetUpstreamRepoBranch'] ?? $Global:DumplingsPreference['WinGetUpstreamRepoBranch'] ?? 'master'
    [string]$OriginRepoOwner = $Task.Config['WinGetOriginRepoOwner'] ?? $Global:DumplingsPreference['WinGetOriginRepoOwner'] ?? $Env:GITHUB_REPOSITORY_OWNER ?? (throw 'The WinGet origin repo owner is unset')
    [string]$OriginRepoName = $Task.Config['WinGetOriginRepoName'] ?? $Global:DumplingsPreference['WinGetOriginRepoName'] ?? 'winget-pkgs'
    [string]$OriginRepoBranch = $Task.Config['WinGetOriginRepoBranch'] ?? $Global:DumplingsPreference['WinGetOriginRepoBranch'] ?? 'master'
    [string]$RootPath = $Task.Config['WinGetRootPath'] ?? $Global:DumplingsPreference['WinGetRootPath'] ?? 'manifests'
    $LocalRepoPath = Get-WinGetLocalRepoPath -RepoName $OriginRepoName -RootPath $RootPath -ErrorAction 'SilentlyContinue'

    [string]$RefPackageIdentifier = $Task.Config['WinGetPackageIdentifier'] ?? $Task.Config.WinGetIdentifier
    try { $null = Test-YamlObject -InputObject $RefPackageIdentifier -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageIdentifier -WarningAction Stop } catch { throw "The PackageIdentifier `"${RefPackageIdentifier}`" is invalid: ${_}" }
    [string]$NewPackageIdentifier = $Task.Config['WinGetNewPackageIdentifier'] ?? $Task.Config['WinGetNewIdentifier'] ?? $RefPackageIdentifier
    try { $null = Test-YamlObject -InputObject $NewPackageIdentifier -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageIdentifier -WarningAction Stop } catch { throw "The PackageIdentifier `"${NewPackageIdentifier}`" is invalid: ${_}" }
    [string]$NewPackageVersion = $Task.CurrentState.Contains('RealVersion') ? $Task.CurrentState.RealVersion : $Task.CurrentState.Version
    try { $null = Test-YamlObject -InputObject $NewPackageVersion -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageVersion -WarningAction Stop } catch { throw "The PackageVersion `"${NewPackageVersion}`" is invalid: ${_}" }
    $RefPackageVersion = ($LocalRepoPath -and (Test-Path -Path $LocalRepoPath) ? (Get-WinGetLocalPackageVersion -PackageIdentifier $RefPackageIdentifier -RootPath $LocalRepoPath) : (Get-WinGetGitHubPackageVersion -PackageIdentifier $RefPackageIdentifier -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $OriginRepoBranch -RootPath $RootPath)) | Select-Object -Last 1
    if (-not $RefPackageVersion) { throw "Could not find any version of the package ${RefPackageIdentifier}" }

    $NewManifestsPath = (New-Item -Path (Join-Path $Global:DumplingsOutput 'WinGet' $NewPackageIdentifier $NewPackageVersion) -ItemType Directory -Force).FullName
    $NewBranchName = "${NewPackageIdentifier}-${NewPackageVersion}-$(Get-Random)" -replace '[\~,\^,\:,\\,\?,\@\{,\*,\[,\s]{1,}|[.lock|/|\.]*$|^\.{1,}|\.\.', ''
    $NewCommitType = if ($Global:DumplingsPreference['NewCommitType']) { $Global:DumplingsPreference.NewCommitType }
    elseif ($NewPackageIdentifier -cne $RefPackageIdentifier) { 'New package' }
    else {
      switch (([Versioning]$NewPackageVersion).CompareTo([Versioning]$RefPackageVersion)) {
        { $_ -gt 0 } { 'New version'; continue }
        0 { 'Update'; continue }
        { $_ -lt 0 } { 'Add version'; continue }
      }
    }
    $NewCommitName = "${NewCommitType}: ${NewPackageIdentifier} version ${NewPackageVersion}$($Task.CurrentState.Contains('RealVersion') ? " ($($Task.CurrentState.Version))" : '')"

    $Script:GitHubTokenUsername ??= (Get-WinGetGitHubApiTokenUser).login
    #endregion

    #region Check existing pull requests in the upstream repo
    $PullRequests = $null
    $SelfPullRequests = $null
    $OtherPullRequests = $null
    if ($Global:DumplingsPreference['SkipPRCheck'] -or $Task.Config['SkipPRCheck']) { $Task.Log('Skip checking pull requests in the upstream repo as configured', 'Info') }
    elseif ($Global:DumplingsPreference['Dry']) { $Task.Log('Skip checking pull requests in the upstream repo in dry mode', 'Info') }
    else {
      $Task.Log('Checking existing pull requests in the upstream repo', 'Verbose')
      try {
        $PullRequests = (Find-WinGetGitHubPullRequest -Query "is:pr repo:${UpstreamRepoOwner}/${UpstreamRepoName} $($NewPackageIdentifier.Replace('.', '/'))/${NewPackageVersion} in:path is:open").items | Where-Object -FilterScript { $_.title -match "(\s|^)$([regex]::Escape($NewPackageIdentifier))(\s|$)" -and $_.title -match "(\s|^)$([regex]::Escape($NewPackageVersion))(\s|$)" }
      } catch {
        $Task.Log("Failed to check existing pull requests in the upstream repo: ${_}", 'Warning')
      }
      if ($PullRequests) {
        $PullRequestsMessage = "Found existing pull requests in the upstream repo ${UpstreamRepoOwner}/${UpstreamRepoName}."
        if ($Script:GitHubTokenUsername -and ($SelfPullRequests = $PullRequests | Where-Object -FilterScript { $_.user.login -ceq $Script:GitHubTokenUsername })) {
          $PullRequestsMessage += "`nPull requests created by the user (${Script:GitHubTokenUsername}):`n$($SelfPullRequests | Select-Object -First 3 | ForEach-Object -Process { "$($_.title) - $($_.html_url)" } | Join-String -Separator "`n")"
        }
        if ($OtherPullRequests = $PullRequests | Where-Object -FilterScript { -not ($Script:GitHubTokenUsername) -or $_.user.login -cne $Script:GitHubTokenUsername }) {
          $PullRequestsMessage += "`nPull requests created by other users:`n$($OtherPullRequests | Select-Object -First 3 | ForEach-Object -Process { "$($_.title) - $($_.html_url)" } | Join-String -Separator "`n")"
        }
        if ($Global:DumplingsPreference['Force']) {
          $PullRequestsMessage += "`nThe existing pull requests will be ignored in force mode"
          $Task.Log($PullRequestsMessage, 'Warning')
        } elseif ($Global:DumplingsPreference['IgnorePRCheck'] -or $Task.Config['IgnorePRCheck']) {
          $PullRequestsMessage += "`nThe existing pull requests will be ignored as configured"
          $Task.Log($PullRequestsMessage, 'Warning')
        } elseif ($OtherPullRequests) {
          $PullRequestsMessage += "`nThe process will be terminated"
          throw $PullRequestsMessage
        } else {
          $PullRequestsMessage += "`nThe existing pull requests created by the user will be closed"
          $Task.Log($PullRequestsMessage, 'Info')
        }
      }
    }
    #endregion

    #region Generate manifests
    # Map the release date to the installer entries
    if ($Task.CurrentState['ReleaseTime']) {
      $ReleaseDate = $Task.CurrentState.ReleaseTime -is [datetime] -or $Task.CurrentState.ReleaseTime -is [System.DateTimeOffset] ? $Task.CurrentState.ReleaseTime.ToUniversalTime().ToString('yyyy-MM-dd') : ($Task.CurrentState.ReleaseTime | Get-Date -Format 'yyyy-MM-dd')
      $Task.CurrentState.Installer | ForEach-Object -Process { $_.ReleaseDate = $_.Contains('ReleaseDate') ? $_ -is [datetime] -or $_ -is [System.DateTimeOffset] ? $_.ToUniversalTime().ToString('yyyy-MM-dd') : ($_ | Get-Date -Format 'yyyy-MM-dd') : $ReleaseDate }
    }
    # Read the manifests
    if ($LocalRepoPath -and (Test-Path -Path $LocalRepoPath)) {
      $Task.Log("Reading existing manifests from local repo at $LocalRepoPath", 'Verbose')
      $RefManifestsObject = Read-WinGetLocalManifests -PackageIdentifier $RefPackageIdentifier -PackageVersion $RefPackageVersion -RootPath $LocalRepoPath | Convert-WinGetManifestsFromYaml
    } else {
      $RefManifestsObject = Read-WinGetGitHubManifests -PackageIdentifier $RefPackageIdentifier -PackageVersion $RefPackageVersion -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $OriginRepoBranch -RootPath $RootPath | Convert-WinGetManifestsFromYaml
    }
    # Update the manifests
    $NewManifestsObject = Update-WinGetManifests -NewPackageIdentifier $NewPackageIdentifier -PackageVersion $NewPackageVersion -VersionManifest $RefManifestsObject.Version -InstallerManifest $RefManifestsObject.Installer -LocaleManifests $RefManifestsObject.Locale -InstallerEntries $Task.CurrentState.Installer -LocaleEntries $Task.CurrentState.Locale -InstallerFiles $Task.InstallerFiles -ReplaceInstallers:$Task.Config['WinGetReplaceMode'] -Logger $Task.Log
    $NewManifests = $NewManifestsObject | Convert-WinGetManifestsToYaml
    #endregion

    # Validate manifests using WinGet client
    $null = $NewManifests | Add-WinGetLocalManifests -PackageIdentifier $NewPackageIdentifier -Path $NewManifestsPath
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
    $NewCommitSha = Add-WinGetGitHubManifests -PackageIdentifier $NewPackageIdentifier -PackageVersion $NewPackageVersion -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $NewBranchName -RepoSha $NewBranch.object.sha -RootPath $RootPath -Manifest $NewManifests -CommitMessage $NewCommitName

    #region Remove old manifests
    # Remove old manifests, if
    # 1. The task is configured to remove the last version, or
    # 2. No installer URL is changed compared with the last state while the version is updated
    $RemoveLastVersionReason = $null
    if ($Task.Config.Contains('RemoveLastVersion')) {
      if ($Task.Config.RemoveLastVersion) { $RemoveLastVersionReason = 'This task is configured to remove the last version' }
      # If RemoveLastVersion is set to 'false', do not remove the last version
    } elseif (($RefPackageIdentifier -ceq $NewPackageIdentifier) -and ($RefPackageVersion -cne $NewPackageVersion) -and (Compare-Object -ReferenceObject $RefManifestsObject -DifferenceObject $NewManifestsObject -Property { $_.Installer.Installers.InstallerUrl } -ExcludeDifferent -IncludeEqual)) {
      $RemoveLastVersionReason = 'At least one of the installer URLs is unchanged compared with the old manifests while the version is updated'
    }
    if ($RemoveLastVersionReason) {
      if ($RefPackageVersion -cne $NewPackageVersion) {
        $Task.Log("Removing the manifests of the last version ${RefPackageVersion}: ${RemoveLastVersionReason}", 'Info')
        $CommitMessage = "Remove version: ${RefPackageIdentifier} version ${RefPackageVersion}"
        $NewCommitSha = Remove-WinGetGitHubManifests -PackageIdentifier $RefPackageIdentifier -PackageVersion $RefPackageVersion -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $NewBranchName -RepoSha $NewCommitSha -RootPath $RootPath -CommitMessage $CommitMessage
      } else {
        $Task.Log("Overriding the manifests of the last version ${RefPackageVersion}: ${RemoveLastVersionReason}", 'Info')
      }
    }
    #endregion

    # Create a pull request in the upstream repo
    $NewPullRequestBody = (Test-Path -Path 'Env:\GITHUB_ACTIONS') ? `
      "Automated by [🥟 ${Env:GITHUB_REPOSITORY_OWNER}/Dumplings](https://github.com/${Env:GITHUB_REPOSITORY_OWNER}/Dumplings) in workflow run [#${Env:GITHUB_RUN_NUMBER}](https://github.com/${Env:GITHUB_REPOSITORY_OWNER}/Dumplings/actions/runs/${Env:GITHUB_RUN_ID})." : `
      "Created by [🥟 Dumplings](https://github.com/${OriginRepoOwner}/Dumplings)."
    $NewPullRequest = New-WinGetGitHubPullRequest -Title $NewCommitName -Body $NewPullRequestBody -Head "${OriginRepoOwner}:${NewBranchName}" -Base $UpstreamRepoBranch -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
    $Task.Log("Pull request created: $($NewPullRequest.title) - $($NewPullRequest.html_url)", 'Info')

    # Close the old pull requests created by the bot user
    if ($SelfPullRequests -and -not ($Global:DumplingsPreference['KeepOldPRs'] -or $Task.Config['KeepOldPRs'])) {
      $SelfPullRequests | ForEach-Object -Process {
        Close-WinGetGitHubPullRequest -PullRequestNumber $_.number -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
        $Task.Log("Closed old pull request of the same version: $($_.title) - $($_.html_url)", 'Info')
      }
    }

    # Close the old pull requests of the same package created by the bot user if RemoveLastVersionReason is set
    if ($RemoveLastVersionReason -and $Script:GitHubTokenUsername -and ($SelfPackagePullRequests = (Find-WinGetGitHubPullRequest -Query "is:pr repo:${UpstreamRepoOwner}/${UpstreamRepoName} $($NewPackageIdentifier.Replace('.', '/')) in:path is:open author:${Script:GitHubTokenUsername}").items | Where-Object -FilterScript { $_.title -match "(\s|^)$([regex]::Escape($NewPackageIdentifier))(\s|$)" })) {
      $SelfPackagePullRequests | Where-Object -FilterScript { $_.number -ne $NewPullRequest.number } | ForEach-Object -Process {
        Close-WinGetGitHubPullRequest -PullRequestNumber $_.number -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
        $Task.Log("Closed old pull request of the same package: $($_.title) - $($_.html_url)", 'Info')
      }
    }
  }
}

Export-ModuleMember -Function '*'
