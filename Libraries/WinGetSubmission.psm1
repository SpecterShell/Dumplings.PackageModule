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

function ConvertTo-WinGetGitHubFileChangeFingerprint {
  <#
  .SYNOPSIS
    Convert GitHub changed-file objects into deterministic change identities.
  .DESCRIPTION
    Exact submission comparison needs more than filenames. Added, modified,
    copied, and renamed files include the resulting Git blob SHA; removals are
    identified by path and status because no resulting blob exists. Renames also
    retain the previous path. Input order does not affect the result.
  .PARAMETER FileChange
    File objects returned by the compare or pull-request files GitHub APIs.
  .OUTPUTS
    Ordinally sorted JSON identities suitable for exact sequence comparison.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(ValueFromPipeline)]
    [AllowNull()]
    [object[]]$FileChange
  )

  begin {
    $Fingerprints = [System.Collections.Generic.List[string]]::new()
  }

  process {
    foreach ($Change in @($FileChange)) {
      if ($null -eq $Change) { continue }

      # GitHub responses are PSCustomObjects, while synthetic callers may use
      # dictionaries. Read both without relying on PowerShell's property adapter.
      $ReadValue = {
        param ($InputObject, [string]$Name)
        if ($InputObject -is [System.Collections.IDictionary]) {
          if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
          return $null
        }
        $Property = $InputObject.PSObject.Properties[$Name]
        return $null -ne $Property ? $Property.Value : $null
      }

      $FileName = [string](& $ReadValue $Change 'filename')
      $Status = [string](& $ReadValue $Change 'status')
      if ([string]::IsNullOrWhiteSpace($FileName) -or [string]::IsNullOrWhiteSpace($Status)) {
        throw 'A GitHub file change is missing its filename or status and cannot be compared exactly.'
      }

      $NormalizedStatus = $Status.ToLowerInvariant()
      $BlobSha = $NormalizedStatus -eq 'removed' ? '' : [string](& $ReadValue $Change 'sha')
      if ($NormalizedStatus -ne 'removed' -and [string]::IsNullOrWhiteSpace($BlobSha)) {
        throw "GitHub did not return a resulting blob SHA for changed file '${FileName}'."
      }

      $Identity = [ordered]@{
        FileName         = $FileName
        Status           = $NormalizedStatus
        PreviousFileName = [string](& $ReadValue $Change 'previous_filename')
        BlobSha          = $BlobSha
      }
      $Fingerprints.Add(($Identity | ConvertTo-Json -Compress))
    }
  }

  end {
    [string[]]$Result = $Fingerprints.ToArray()
    [Array]::Sort($Result, [StringComparer]::Ordinal)
    return $Result
  }
}

function Test-WinGetGitHubFileChangeEquality {
  <#
  .SYNOPSIS
    Test whether two GitHub file-change collections describe the same change.
  .PARAMETER ReferenceChange
    Existing pull-request file changes.
  .PARAMETER DifferenceChange
    Candidate branch file changes.
  .OUTPUTS
    True only when paths, statuses, rename sources, and resulting blobs match.
  #>
  [OutputType([bool])]
  param (
    [AllowNull()]
    [object[]]$ReferenceChange,
    [AllowNull()]
    [object[]]$DifferenceChange
  )

  $ReferenceFingerprint = @(ConvertTo-WinGetGitHubFileChangeFingerprint -FileChange $ReferenceChange)
  $DifferenceFingerprint = @(ConvertTo-WinGetGitHubFileChangeFingerprint -FileChange $DifferenceChange)
  if ($ReferenceFingerprint.Count -ne $DifferenceFingerprint.Count) { return $false }

  for ($Index = 0; $Index -lt $ReferenceFingerprint.Count; $Index++) {
    if ($ReferenceFingerprint[$Index] -cne $DifferenceFingerprint[$Index]) { return $false }
  }
  return $true
}

function Select-WinGetPullRequestForClosure {
  <#
  .SYNOPSIS
    Select unique pull requests that have not already been closed in this run.
  .PARAMETER PullRequest
    Pull request objects to consider.
  .PARAMETER ExcludedNumber
    Pull request numbers that must not be selected, including newly created or
    already closed pull requests.
  .OUTPUTS
    Unique pull request objects in their original order.
  #>
  [OutputType([object[]])]
  param (
    [AllowNull()]
    [object[]]$PullRequest,
    [AllowNull()]
    [long[]]$ExcludedNumber
  )

  $Excluded = [System.Collections.Generic.HashSet[long]]::new()
  foreach ($Number in @($ExcludedNumber)) { $null = $Excluded.Add($Number) }
  $Selected = [System.Collections.Generic.List[object]]::new()
  $Seen = [System.Collections.Generic.HashSet[long]]::new()

  foreach ($Item in @($PullRequest)) {
    if ($null -eq $Item) { continue }
    $Number = [long]$Item.number
    if ($Number -gt 0 -and -not $Excluded.Contains($Number) -and $Seen.Add($Number)) {
      $Selected.Add($Item)
    }
  }

  return $Selected.ToArray()
}

function Invoke-WinGetSubmissionCandidateBranchCleanup {
  <#
  .SYNOPSIS
    Best-effort cleanup for a candidate branch that will not become a pull request.
  .PARAMETER Task
    Package task used for structured logging.
  .PARAMETER BranchName
    Candidate branch to remove.
  .PARAMETER RepoOwner
    Owner of the fork containing the candidate branch.
  .PARAMETER RepoName
    Name of the fork containing the candidate branch.
  #>
  param (
    [Parameter(Mandatory)]$Task,
    [Parameter(Mandatory)][string]$BranchName,
    [Parameter(Mandatory)][string]$RepoOwner,
    [Parameter(Mandatory)][string]$RepoName
  )

  try {
    $null = Remove-WinGetGitHubBranch -Name $BranchName -RepoOwner $RepoOwner -RepoName $RepoName
    $Task.Log("Removed unused candidate branch ${RepoOwner}:${BranchName}", 'Verbose')
  } catch {
    # Submission is intentionally aborted even if cleanup fails. Report the
    # orphaned branch without replacing the more important no-op decision.
    $Task.Log("Failed to remove unused candidate branch ${RepoOwner}:${BranchName}: ${_}", 'Warning')
  }
}

function Test-WinGetInstallerUrlIntersection {
  <#
  .SYNOPSIS
    Test whether two installer collections contain an identical installer URL.
  .DESCRIPTION
    Reads InstallerUrl explicitly from dictionary-backed or object-backed
    installer entries and performs an ordinal set comparison. Compare-Object's
    -Property adapter cannot read keys from OrderedDictionary instances and
    therefore incorrectly treats every missing adapted property as equal.
  .PARAMETER ReferenceInstaller
    Installer entries from the existing manifest version.
  .PARAMETER DifferenceInstaller
    Installer entries from the newly generated manifest version.
  .OUTPUTS
    True when at least one non-empty InstallerUrl occurs in both collections;
    otherwise false.
  #>
  [OutputType([bool])]
  param (
    [AllowNull()]
    [object[]]$ReferenceInstaller,
    [AllowNull()]
    [object[]]$DifferenceInstaller
  )

  # URL paths and query strings can be case-sensitive. Compare the authored
  # manifest values exactly instead of applying culture or URI normalization.
  $ReferenceUrls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($Installer in @($ReferenceInstaller)) {
    if ($null -eq $Installer) { continue }

    # Logical WinGet models normally use ordered dictionaries, while callers
    # and tests may provide PSCustomObject entries. Read both representations.
    $InstallerUrl = if ($Installer -is [System.Collections.IDictionary]) {
      if ($Installer.Contains('InstallerUrl')) { [string]$Installer['InstallerUrl'] }
    } else {
      $Property = $Installer.PSObject.Properties['InstallerUrl']
      if ($null -ne $Property) { [string]$Property.Value }
    }

    if (-not [string]::IsNullOrWhiteSpace($InstallerUrl)) {
      $null = $ReferenceUrls.Add($InstallerUrl)
    }
  }

  if ($ReferenceUrls.Count -eq 0) { return $false }

  foreach ($Installer in @($DifferenceInstaller)) {
    if ($null -eq $Installer) { continue }
    $InstallerUrl = if ($Installer -is [System.Collections.IDictionary]) {
      if ($Installer.Contains('InstallerUrl')) { [string]$Installer['InstallerUrl'] }
    } else {
      $Property = $Installer.PSObject.Properties['InstallerUrl']
      if ($null -ne $Property) { [string]$Property.Value }
    }

    if (-not [string]::IsNullOrWhiteSpace($InstallerUrl) -and $ReferenceUrls.Contains($InstallerUrl)) {
      return $true
    }
  }

  return $false
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
    # 2. At least one installer URL is unchanged while the version is updated
    $RemoveLastVersionReason = $null
    if ($Task.Config.Contains('RemoveLastVersion')) {
      if ($Task.Config.RemoveLastVersion) { $RemoveLastVersionReason = 'This task is configured to remove the last version' }
      # If RemoveLastVersion is set to 'false', do not remove the last version
    } elseif (($RefPackageIdentifier -ceq $NewPackageIdentifier) -and ($RefPackageVersion -cne $NewPackageVersion) -and (Test-WinGetInstallerUrlIntersection -ReferenceInstaller $RefManifest.Installers -DifferenceInstaller $NewManifest.Installers)) {
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

    # Compare the final candidate branch with the branch that the pull request
    # would merge into. Creating commits can still result in an empty effective
    # diff when an earlier automation pull request has already been merged.
    $Task.Log('Checking the final candidate branch for effective changes', 'Verbose')
    try {
      $CandidateComparison = Get-WinGetGitHubComparison -Base "${UpstreamRepoOwner}:${UpstreamRepoBranch}" -Head "${OriginRepoOwner}:${NewBranchName}" -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
      $CandidateChanges = @($CandidateComparison.files)
    } catch {
      Invoke-WinGetSubmissionCandidateBranchCleanup -Task $Task -BranchName $NewBranchName -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName
      throw "Failed to compare the candidate branch with ${UpstreamRepoOwner}/${UpstreamRepoName}:${UpstreamRepoBranch}: ${_}"
    }

    if ($CandidateChanges.Count -eq 0) {
      $Task.Log("The candidate branch has no changes compared with ${UpstreamRepoOwner}/${UpstreamRepoName}:${UpstreamRepoBranch}. No pull request is necessary.", 'Info')
      Invoke-WinGetSubmissionCandidateBranchCleanup -Task $Task -BranchName $NewBranchName -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName
      return
    }

    # Only compare existing self-authored pull requests when the normal cleanup
    # policy would close them. Keeping an identical PR preserves its completed or
    # in-progress validation results and avoids submitting a redundant branch.
    $ShouldCloseSelfPullRequests = $SelfPullRequests -and -not ($Global:DumplingsPreference['KeepOldPRs'] -or $Task.Config['KeepOldPRs'])
    if ($ShouldCloseSelfPullRequests) {
      # GitHub caps the compare endpoint's file collection at 300. A full page
      # cannot prove that more files were not omitted, so fail closed rather than
      # incorrectly declaring a large candidate identical to an existing PR.
      if ($CandidateChanges.Count -ge 300) {
        Invoke-WinGetSubmissionCandidateBranchCleanup -Task $Task -BranchName $NewBranchName -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName
        throw 'The candidate branch comparison returned 300 files, so GitHub may have truncated the result and exact duplicate-PR comparison is unsafe.'
      }

      foreach ($ExistingPullRequest in @($SelfPullRequests)) {
        try {
          $ExistingChanges = @(Get-WinGetGitHubPullRequestFile -PullRequestNumber $ExistingPullRequest.number -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName)
          $ChangesAreIdentical = Test-WinGetGitHubFileChangeEquality -ReferenceChange $ExistingChanges -DifferenceChange $CandidateChanges
        } catch {
          Invoke-WinGetSubmissionCandidateBranchCleanup -Task $Task -BranchName $NewBranchName -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName
          throw "Failed to compare candidate changes with existing pull request #$($ExistingPullRequest.number): ${_}"
        }

        if ($ChangesAreIdentical) {
          $Task.Log("Existing pull request #$($ExistingPullRequest.number) contains exactly the same changes. Preserving it and aborting redundant submission: $($ExistingPullRequest.html_url)", 'Info')
          Invoke-WinGetSubmissionCandidateBranchCleanup -Task $Task -BranchName $NewBranchName -RepoOwner $OriginRepoOwner -RepoName $OriginRepoName
          return
        }
      }
    }

    # Create a pull request in the upstream repo
    $NewPullRequestBody = (Test-Path -Path 'Env:\GITHUB_ACTIONS') ? `
      "Automated by [🥟 ${Env:GITHUB_REPOSITORY_OWNER}/Dumplings](https://github.com/${Env:GITHUB_REPOSITORY_OWNER}/Dumplings) in workflow run [#${Env:GITHUB_RUN_NUMBER}](https://github.com/${Env:GITHUB_REPOSITORY_OWNER}/Dumplings/actions/runs/${Env:GITHUB_RUN_ID})." : `
      "Created by [🥟 Dumplings](https://github.com/${OriginRepoOwner}/Dumplings)."
    $NewPullRequest = New-WinGetGitHubPullRequest -Title $NewCommitName -Body $NewPullRequestBody -Head "${OriginRepoOwner}:${NewBranchName}" -Base $UpstreamRepoBranch -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
    $Task.Log("Pull request created: $($NewPullRequest.title) - $($NewPullRequest.html_url)", 'Info')

    # GitHub search can continue returning an item briefly after it is closed.
    # Keep a run-local exclusion set so the broader package cleanup never sends
    # a second close request for a pull request handled above.
    $ClosedPullRequestNumbers = [System.Collections.Generic.HashSet[long]]::new()

    # Close the old pull requests created by the bot user
    if ($ShouldCloseSelfPullRequests) {
      Select-WinGetPullRequestForClosure -PullRequest $SelfPullRequests -ExcludedNumber $NewPullRequest.number | ForEach-Object -Process {
        Close-WinGetGitHubPullRequest -PullRequestNumber $_.number -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
        $null = $ClosedPullRequestNumbers.Add([long]$_.number)
        $Task.Log("Closed old pull request of the same version: $($_.title) - $($_.html_url)", 'Info')
      }
    }

    # Close the old pull requests of the same package created by the bot user if RemoveLastVersionReason is set
    if ($RemoveLastVersionReason -and $Script:GitHubTokenUsername -and ($SelfPackagePullRequests = (Find-WinGetGitHubPullRequest -Query "is:pr repo:${UpstreamRepoOwner}/${UpstreamRepoName} $($NewPackageIdentifier.Replace('.', '/')) in:path is:open author:${Script:GitHubTokenUsername}").items | Where-Object -FilterScript { $_.title -match "(\s|^)$([regex]::Escape($NewPackageIdentifier))(\s|$)" })) {
      $ExcludedPullRequestNumbers = [long[]]@($ClosedPullRequestNumbers) + [long]$NewPullRequest.number
      Select-WinGetPullRequestForClosure -PullRequest $SelfPackagePullRequests -ExcludedNumber $ExcludedPullRequestNumbers | ForEach-Object -Process {
        Close-WinGetGitHubPullRequest -PullRequestNumber $_.number -RepoOwner $UpstreamRepoOwner -RepoName $UpstreamRepoName
        $null = $ClosedPullRequestNumbers.Add([long]$_.number)
        $Task.Log("Closed old pull request of the same package: $($_.title) - $($_.html_url)", 'Info')
      }
    }
  }
}

Export-ModuleMember -Function '*'
