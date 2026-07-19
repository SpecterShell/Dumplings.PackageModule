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

$GitHubTokenUsername = $null

function Get-WinGetPullRequestConflictInfo {
  <#
  .SYNOPSIS
    Classify matching WinGet pull requests for duplicate-submission handling.
  .DESCRIPTION
    Pull requests created by the GitHub token owner are always classified as
    self-authored and never block submission. When a blocking-user list is in
    use, only other authors in that case-insensitive list block submission.
    Without a configured list, every other pull request blocks as before.
  .PARAMETER PullRequest
    Matching open pull request objects returned by the GitHub search API.
  .PARAMETER TokenUsername
    Login associated with the GitHub API token. Matching pull requests are
    excluded from blocking even if the login also appears in BlockingUsername.
  .PARAMETER BlockingUsername
    Optional GitHub logins whose pull requests should block submission.
  .PARAMETER UseConfiguredBlockingUsers
    Apply BlockingUsername as an allowlist of blocking authors. Without this
    switch, all authors other than TokenUsername are considered blocking.
  .OUTPUTS
    An object containing SelfPullRequests, BlockingPullRequests,
    IgnoredPullRequests, and the normalized configured usernames.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ValueFromPipeline)]
    [AllowNull()]
    [object[]]$PullRequest,
    [AllowNull()]
    [string]$TokenUsername,
    [AllowNull()]
    [AllowEmptyCollection()]
    [object[]]$BlockingUsername,
    [switch]$UseConfiguredBlockingUsers
  )

  begin {
    # GitHub logins are case-insensitive, so normalize membership through an
    # ordinal-ignore-case set while retaining the API objects for diagnostics.
    $ConfiguredUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Username in @($BlockingUsername)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Username)) {
        $null = $ConfiguredUsers.Add(([string]$Username).Trim())
      }
    }
    $SelfPullRequests = [System.Collections.Generic.List[object]]::new()
    $BlockingPullRequests = [System.Collections.Generic.List[object]]::new()
    $IgnoredPullRequests = [System.Collections.Generic.List[object]]::new()
  }

  process {
    foreach ($Item in @($PullRequest)) {
      if ($null -eq $Item) { continue }
      $Author = [string]$Item.user.login

      # The token owner's PRs are managed after submission and never represent
      # a competing submission, regardless of the configured blocking list.
      if (-not [string]::IsNullOrWhiteSpace($TokenUsername) -and $Author -ieq $TokenUsername) {
        $SelfPullRequests.Add($Item)
      } elseif (-not $UseConfiguredBlockingUsers -or $ConfiguredUsers.Contains($Author)) {
        $BlockingPullRequests.Add($Item)
      } else {
        $IgnoredPullRequests.Add($Item)
      }
    }
  }

  end {
    [pscustomobject]@{
      SelfPullRequests        = $SelfPullRequests.ToArray()
      BlockingPullRequests    = $BlockingPullRequests.ToArray()
      IgnoredPullRequests     = $IgnoredPullRequests.ToArray()
      ConfiguredBlockingUsers = @($ConfiguredUsers | Sort-Object)
      UsesConfiguredUserList  = [bool]$UseConfiguredBlockingUsers
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
    if (-not (Test-YamlObject -InputObject $RefPackageIdentifier -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageIdentifier)) { throw "The PackageIdentifier `"${RefPackageIdentifier}`" is invalid" }
    [string]$NewPackageIdentifier = $Task.Config['WinGetNewPackageIdentifier'] ?? $Task.Config['WinGetNewIdentifier'] ?? $RefPackageIdentifier
    if (-not (Test-YamlObject -InputObject $NewPackageIdentifier -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageIdentifier)) { throw "The PackageIdentifier `"${NewPackageIdentifier}`" is invalid" }
    [string]$NewPackageVersion = $Task.CurrentState.Contains('RealVersion') ? $Task.CurrentState.RealVersion : $Task.CurrentState.Version
    if (-not (Test-YamlObject -InputObject $NewPackageVersion -Schema (Get-WinGetManifestSchema -ManifestType version).properties.PackageVersion)) { throw "The PackageVersion `"${NewPackageVersion}`" is invalid" }
    $RefPackageVersion = ($LocalRepoPath -and (Test-Path -Path $LocalRepoPath) ? (Get-WinGetLocalPackageVersion -PackageIdentifier $RefPackageIdentifier -RootPath $LocalRepoPath) : (Get-WinGetGitHubPackageVersion -PackageIdentifier $RefPackageIdentifier -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $OriginRepoBranch -RootPath $RootPath)) | Select-Object -Last 1
    if (-not $RefPackageVersion) { throw "Could not find any version of the package ${RefPackageIdentifier}" }

    $NewManifestsPath = (New-Item -Path (Join-Path $Global:DumplingsOutput 'WinGet' $NewPackageIdentifier $NewPackageVersion) -ItemType Directory -Force).FullName
    $NewBranchName = "${NewPackageIdentifier}-${NewPackageVersion}-$(Get-Random)" -replace '[\~,\^,\:,\\,\?,\@\{,\*,\[,\s]{1,}|[.lock|/|\.]*$|^\.{1,}|\.\.', ''
    $NewCommitType = if ($Global:DumplingsPreference['NewCommitType']) { $Global:DumplingsPreference.NewCommitType }
    elseif ($NewPackageIdentifier -cne $RefPackageIdentifier) { 'New package' }
    else {
      switch (([WinGetVersion]$NewPackageVersion).CompareTo([WinGetVersion]$RefPackageVersion)) {
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
    $BlockingPullRequests = $null
    $IgnoredPullRequests = $null
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
        # A null or absent preference preserves the legacy all-other-users
        # behavior. An explicitly empty YAML list intentionally blocks nobody.
        $ConfiguredBlockingUsers = $Global:DumplingsPreference['WinGetBlockingPullRequestUsers']
        $UseConfiguredBlockingUsers = $null -ne $ConfiguredBlockingUsers
        $PullRequestInfo = Get-WinGetPullRequestConflictInfo -PullRequest $PullRequests -TokenUsername $Script:GitHubTokenUsername -BlockingUsername @($ConfiguredBlockingUsers) -UseConfiguredBlockingUsers:$UseConfiguredBlockingUsers
        $SelfPullRequests = $PullRequestInfo.SelfPullRequests
        $BlockingPullRequests = $PullRequestInfo.BlockingPullRequests
        $IgnoredPullRequests = $PullRequestInfo.IgnoredPullRequests

        $PullRequestsMessage = "Found existing pull requests in the upstream repo ${UpstreamRepoOwner}/${UpstreamRepoName}."
        if ($SelfPullRequests) {
          $PullRequestsMessage += "`nPull requests created by the user (${Script:GitHubTokenUsername}):`n$($SelfPullRequests | Select-Object -First 3 | ForEach-Object -Process { "$($_.title) - $($_.html_url)" } | Join-String -Separator "`n")"
        }
        if ($BlockingPullRequests) {
          $PullRequestsMessage += "`nPull requests that block submission:`n$($BlockingPullRequests | Select-Object -First 3 | ForEach-Object -Process { "$($_.title) - $($_.html_url) (@$($_.user.login))" } | Join-String -Separator "`n")"
        }
        if ($IgnoredPullRequests) {
          $PullRequestsMessage += "`nPull requests ignored because their authors are not configured to block submission:`n$($IgnoredPullRequests | Select-Object -First 3 | ForEach-Object -Process { "$($_.title) - $($_.html_url) (@$($_.user.login))" } | Join-String -Separator "`n")"
        }
        if ($Global:DumplingsPreference['Force']) {
          $PullRequestsMessage += "`nThe existing pull requests will be ignored in force mode"
          $Task.Log($PullRequestsMessage, 'Warning')
        } elseif ($Global:DumplingsPreference['IgnorePRCheck'] -or $Task.Config['IgnorePRCheck']) {
          $PullRequestsMessage += "`nThe existing pull requests will be ignored as configured"
          $Task.Log($PullRequestsMessage, 'Warning')
        } elseif ($BlockingPullRequests) {
          $PullRequestsMessage += "`nThe process will be terminated"
          throw $PullRequestsMessage
        } else {
          if ($SelfPullRequests) { $PullRequestsMessage += "`nThe existing pull requests created by the token user will be closed" }
          if ($IgnoredPullRequests) { $PullRequestsMessage += "`nThe non-blocking pull requests will be ignored" }
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
      $RefManifest = Read-WinGetLocalManifests -PackageIdentifier $RefPackageIdentifier -PackageVersion $RefPackageVersion -RootPath $LocalRepoPath | ConvertFrom-WinGetManifestYaml
    } else {
      $RefManifest = Read-WinGetGitHubManifests -PackageIdentifier $RefPackageIdentifier -PackageVersion $RefPackageVersion -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName -RepoBranch $OriginRepoBranch -RootPath $RootPath | ConvertFrom-WinGetManifestYaml
    }
    # Update the manifests
    $NewManifest = Update-WinGetManifest -Manifest $RefManifest -NewPackageIdentifier $NewPackageIdentifier -PackageVersion $NewPackageVersion -InstallerEntries $Task.CurrentState.Installer -LocaleEntries $Task.CurrentState.Locale -InstallerFiles $Task.InstallerFiles -ReplaceInstallers:$Task.Config['WinGetReplaceMode'] -Logger $Task.Log
    $NewManifests = $NewManifest | ConvertTo-WinGetManifestYaml
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
    } elseif (($RefPackageIdentifier -ceq $NewPackageIdentifier) -and ($RefPackageVersion -cne $NewPackageVersion) -and (Compare-Object -ReferenceObject @($RefManifest.Installers) -DifferenceObject @($NewManifest.Installers) -Property InstallerUrl -ExcludeDifferent -IncludeEqual)) {
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
