#Requires -Version 7.4
# SPDX-License-Identifier: Apache-2.0
# Opt-in references for packages awaiting their first merge. GitHub PR metadata
# identifies the trusted author and immutable head; the complete file delta
# must prove a single-version addition before any manifest is used or changed.
# API reference: https://docs.github.com/en/rest/pulls/pulls

function Get-WinGetPendingPackageReference {
  <#
  .SYNOPSIS
    Select the highest added manifest version from recent trusted, open PRs.
  .DESCRIPTION
    Reads only addition-only, single-package, single-version PRs. Content is
    pinned to a captured SHA and validated locally. Search titles narrow the
    candidates but never supply the package identity or version.
  .PARAMETER Task
    Task used to log rejected candidates and bounded-search warnings.
  .PARAMETER PackageIdentifier
    Exact package identifier missing from the configured reference repository.
  .PARAMETER TrustedUser
    Explicit GitHub author allowlist. Empty lists are rejected.
  .PARAMETER RepoOwner
    Upstream repository owner.
  .PARAMETER RepoName
    Upstream repository name.
  .PARAMETER RepoBranch
    Required upstream base branch.
  .PARAMETER RootPath
    Repository-relative manifest root.
  .PARAMETER SearchLimit
    Recent search results examined per trusted account, from 1 through 100.
  .OUTPUTS
    Detached reference containing the PR, pinned content/model, version, and exact changed paths.
  #>
  param (
    [Parameter(Mandatory)]$Task,
    [Parameter(Mandatory)][string]$PackageIdentifier,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$TrustedUser,
    [Parameter(Mandatory)][string]$RepoOwner,
    [Parameter(Mandatory)][string]$RepoName,
    [Parameter(Mandatory)][string]$RepoBranch,
    [Parameter(Mandatory)][string]$RootPath,
    [ValidateRange(1, 100)][int]$SearchLimit = 30
  )

  $TrustedAuthors = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($User in $TrustedUser) {
    if ($User -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$') { throw "Invalid trusted GitHub account: '$User'" }
    $null = $TrustedAuthors.Add($User)
  }
  $Prefix = Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -RootPath $RootPath
  $FilePattern = '^' + [regex]::Escape($Prefix) + '/(?<Version>[^/]+)/' + [regex]::Escape($PackageIdentifier) + '(?:\.installer|\.locale\.[A-Za-z0-9-]+)?\.yaml$'
  $Seen = [Collections.Generic.HashSet[int]]::new()
  $Best = $null

  foreach ($User in $TrustedAuthors) {
    $Search = Find-WinGetGitHubPullRequest -Query "is:pr is:open repo:${RepoOwner}/${RepoName} author:${User} `"${PackageIdentifier}`" in:title sort:updated-desc" -MaximumResults $SearchLimit
    if ($Search.incomplete_results) { throw 'GitHub returned incomplete pending-package search results. Retry before selecting a reference.' }
    if ($Search.total_count -gt $SearchLimit) {
      $Task.Log("Pending-package search for ${User} is limited to the ${SearchLimit} most recently updated PRs. Increase WinGetPendingPackageSearchLimit to inspect more candidates.", 'Warning')
    }

    foreach ($Item in @($Search.items)) {
      if (-not $Seen.Add([int]$Item.number)) { continue }
      try {
        $PullRequest = Get-WinGetGitHubPullRequest -PullRequestNumber $Item.number -RepoOwner $RepoOwner -RepoName $RepoName
        if ($PullRequest.state -ne 'open' -or $PullRequest.draft -or $PullRequest.merged -or -not $TrustedAuthors.Contains([string]$PullRequest.user.login)) { continue }
        if ($PullRequest.base.ref -cne $RepoBranch -or $PullRequest.base.repo.full_name -ine "${RepoOwner}/${RepoName}") { continue }
        if (-not $PullRequest.head.repo -or $PullRequest.head.sha -notmatch '^[a-fA-F0-9]{40}$' -or $PullRequest.head.repo.full_name -notmatch '^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$') { continue }

        # The entire delta must consist of recognized manifest files in one leaf.
        # Removed versions, unrelated edits, renames, and partial file lists are unsafe templates.
        $Files = @(Get-WinGetGitHubPullRequestFile -PullRequestNumber $Item.number -RepoOwner $RepoOwner -RepoName $RepoName)
        if ($Files.Count -lt 3 -or $Files.Count -ne $PullRequest.changed_files) { throw 'The complete multi-file addition could not be established.' }
        $Version = $null
        $Paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($File in $Files) {
          $Match = [regex]::Match([string]$File.filename, $FilePattern)
          if ($File.status -cne 'added' -or -not $Match.Success -or -not $Paths.Add([string]$File.filename)) { throw 'The PR is not a pure single-package manifest addition.' }
          $FileVersion = $Match.Groups['Version'].Value
          if ($FileVersion -in @('.', '..')) { throw 'The version path is invalid.' }
          if ($Version -and $Version -cne $FileVersion) { throw 'The PR adds more than one package version.' }
          $Version = $FileVersion
        }

        # File-list endpoints are live. A second read detects movement before
        # the manifest fetch, which uses the original SHA rather than a branch name.
        $Current = Get-WinGetGitHubPullRequest -PullRequestNumber $Item.number -RepoOwner $RepoOwner -RepoName $RepoName
        if ($Current.state -ne 'open' -or $Current.draft -or $Current.merged -or $Current.head.sha -cne $PullRequest.head.sha -or $Current.base.ref -cne $PullRequest.base.ref -or $Current.base.repo.full_name -ine $PullRequest.base.repo.full_name -or $Current.changed_files -ne $Files.Count) { throw 'The PR changed during reference discovery.' }
        $HeadOwner, $HeadRepo = $PullRequest.head.repo.full_name.Split('/')
        $Content = Read-WinGetGitHubManifests -PackageIdentifier $PackageIdentifier -PackageVersion $Version -RepoOwner $HeadOwner -RepoName $HeadRepo -RepoBranch $PullRequest.head.sha -RootPath $RootPath
        $Manifest = ConvertFrom-WinGetManifestYaml -Content $Content
        if ($Manifest.PackageIdentifier -cne $PackageIdentifier -or $Manifest.PackageVersion -cne $Version -or $Manifest.SourceFormat -eq 'singleton') { throw "Manifest '$($Manifest.PackageIdentifier)' version '$($Manifest.PackageVersion)' format '$($Manifest.SourceFormat)' does not match the PR addition for '${PackageIdentifier}' version '${Version}'." }
        $Validation = Get-WinGetManifestValidationResult -Manifest $Manifest
        if ($Validation.HasErrors) { throw "Reference manifest validation failed: $($Validation.Diagnostics.Where({ $_.Severity -eq 'Error' }).Message -join '; ')" }

        $Reference = [pscustomobject]@{
          PullRequest    = $PullRequest
          PackageVersion = $Version
          RepoOwner      = $HeadOwner
          RepoName       = $HeadRepo
          RepoBranch     = [string]$PullRequest.head.ref
          HeadSha        = [string]$PullRequest.head.sha
          Content        = $Content
          Manifest       = $Manifest
          Paths          = [string[]]@($Paths)
        }
        $Comparison = if ($Best) { ([WinGetVersion]$Version).CompareTo([WinGetVersion]$Best.PackageVersion) } else { 1 }
        if ($Comparison -gt 0 -or ($Comparison -eq 0 -and ([datetimeoffset]$PullRequest.updated_at -gt [datetimeoffset]$Best.PullRequest.updated_at -or ($PullRequest.updated_at -eq $Best.PullRequest.updated_at -and $PullRequest.number -gt $Best.PullRequest.number)))) {
          $Best = $Reference
        }
      } catch {
        $Task.Log("Skipping pending-package reference PR #$($Item.number): $_", 'Warning')
      }
    }
  }
  if (-not $Best) { throw "No trusted open PR provides a valid single-version addition for ${PackageIdentifier}." }
  return $Best
}

function Test-WinGetPendingPackageContentEquality {
  <#
  .SYNOPSIS
    Compare generated YAML with the captured PR files using exact LF-normalized bytes.
  .PARAMETER Reference
    Captured pending-package reference.
  .PARAMETER Content
    Generated raw manifest bundle.
  .PARAMETER PackageVersion
    Generated package version, used in the physical paths.
  .PARAMETER RootPath
    Repository-relative manifest root.
  .OUTPUTS
    True when no file path or content changes are needed.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)]$Reference,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Content,
    [Parameter(Mandatory)][string]$PackageVersion,
    [Parameter(Mandatory)][string]$RootPath
  )
  $Identifier = $Reference.Manifest.PackageIdentifier
  $OldPrefix = Get-WinGetGitHubPackagePath -PackageIdentifier $Identifier -PackageVersion $Reference.PackageVersion -RootPath $RootPath
  $NewPrefix = Get-WinGetGitHubPackagePath -PackageIdentifier $Identifier -PackageVersion $PackageVersion -RootPath $RootPath
  $OldFiles = @(ConvertTo-WinGetGitHubManifestFileAddition -Manifest $Reference.Content -PackageIdentifier $Identifier -Prefix $OldPrefix)
  $NewFiles = @(ConvertTo-WinGetGitHubManifestFileAddition -Manifest $Content -PackageIdentifier $Identifier -Prefix $NewPrefix)
  return Test-ObjectValueEqual -Left @($OldFiles | Sort-Object path) -Right @($NewFiles | Sort-Object path)
}

function Get-WinGetPendingPackageAuthorToken {
  <#
  .SYNOPSIS
    Resolve and verify an optional credential for a pending PR author.
  .DESCRIPTION
    Reads only Core's loaded GitHubPullRequestAuthorTokens secret map. It never
    opens Secret.yaml or changes the default API credential. No mapping returns
    no output. Configured credentials must authenticate as the requested author.
  .PARAMETER Author
    Login from the rechecked upstream PR, matched case-insensitively.
  .OUTPUTS
    The configured string or SecureString token, or no output when unconfigured.
    Callers must pass this value directly to the API and never log it.
  #>
  param ([Parameter(Mandatory)][string]$Author)

  # Independent PackageModule callers may have no Core secret storage.
  $SecretVariable = Get-Variable -Name DumplingsSecret -Scope Global -ErrorAction SilentlyContinue
  if (-not $SecretVariable -or $null -eq $SecretVariable.Value) { return }
  $Secrets = $SecretVariable.Value
  if ($Secrets -isnot [System.Collections.IDictionary]) { throw 'DumplingsSecret must be a dictionary.' }
  if ('GitHubPullRequestAuthorTokens' -notin $Secrets.Keys) { return }
  $Tokens = $Secrets['GitHubPullRequestAuthorTokens']
  if ($Tokens -isnot [System.Collections.IDictionary]) { throw 'GitHubPullRequestAuthorTokens must be a dictionary of GitHub logins to tokens.' }

  # Do not rely on the dictionary's comparer. Standalone callers may supply a
  # case-sensitive map, including ambiguous keys that differ only by casing.
  $Keys = @($Tokens.Keys | Where-Object { $_ -is [string] -and $_ -ieq $Author })
  if (-not $Keys.Count) { return }
  if ($Keys.Count -ne 1) { throw "GitHubPullRequestAuthorTokens has ambiguous entries for '${Author}'." }
  $Token = $Tokens[$Keys[0]]
  if (($Token -isnot [string] -and $Token -isnot [securestring]) -or ($Token -is [string] -and [string]::IsNullOrWhiteSpace($Token)) -or ($Token -is [securestring] -and $Token.Length -eq 0)) {
    throw "The GitHub PR author token for '${Author}' must be a nonempty string or SecureString."
  }

  # Validate identity before any branch commit. Replace probe failures with a
  # safe message because an underlying exception could include the credential.
  try {
    $User = Get-WinGetGitHubApiTokenUser -Token $Token -ErrorAction Stop
  } catch {
    throw "Could not validate the configured GitHub PR author token for '${Author}'. Check the credential and GitHub API access. No changes were made."
  }
  if ([string]$User.login -ine $Author) {
    throw "The configured GitHub PR author token for '${Author}' authenticates as a different account. No changes were made."
  }
  return $Token
}

function Update-WinGetPendingPackagePullRequest {
  <#
  .SYNOPSIS
    Replace a pending version on its existing PR branch and update its title.
  .DESCRIPTION
    Rechecks state and the pinned head, verifies push permission, and combines
    new manifests and obsolete pending paths in one commit. Concurrent human
    changes are never rebased over. Identical manifests skip the commit but can
    repair a stale title. Title failures throw after reporting that the manifests
    are already present. Optional author credentials apply only to title edits
    and are verified before committing. No PR is created or closed.
  .PARAMETER Task
    Task used to log completed updates and unchanged manifests.
  .PARAMETER Reference
    Trusted reference selected by Get-WinGetPendingPackageReference.
  .PARAMETER Content
    Validated generated raw manifest bundle.
  .PARAMETER PackageVersion
    New manifest version.
  .PARAMETER Title
    New PR title and commit headline.
  .PARAMETER RepoOwner
    Upstream PR repository owner.
  .PARAMETER RepoName
    Upstream PR repository name.
  .PARAMETER RootPath
    Repository-relative manifest root.
  #>
  param (
    [Parameter(Mandatory)]$Task,
    [Parameter(Mandatory)]$Reference,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Content,
    [Parameter(Mandatory)][string]$PackageVersion,
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$RepoOwner,
    [Parameter(Mandatory)][string]$RepoName,
    [Parameter(Mandatory)][string]$RootPath
  )

  $Number = $Reference.PullRequest.number
  $Current = Get-WinGetGitHubPullRequest -PullRequestNumber $Number -RepoOwner $RepoOwner -RepoName $RepoName
  if ($Current.state -ne 'open' -or $Current.merged -or $Current.draft -or $Current.head.sha -cne $Reference.HeadSha -or $Current.head.ref -cne $Reference.RepoBranch -or $Current.head.repo.full_name -ine "$($Reference.RepoOwner)/$($Reference.RepoName)" -or $Current.user.login -ine $Reference.PullRequest.user.login -or $Current.base.ref -cne $Reference.PullRequest.base.ref -or $Current.base.repo.full_name -ine $Reference.PullRequest.base.repo.full_name) {
    throw "Referenced PR #${Number} changed or closed. Rerun before updating it."
  }
  $CurrentFiles = @(Get-WinGetGitHubPullRequestFile -PullRequestNumber $Number -RepoOwner $RepoOwner -RepoName $RepoName)
  if ($CurrentFiles.Count -ne $Reference.Paths.Count -or $CurrentFiles.Where({ $_.status -cne 'added' -or $_.filename -cnotin $Reference.Paths }).Count) {
    throw "PR #${Number} no longer has the captured addition-only file delta. Rerun before updating it."
  }
  $NeedsTitleUpdate = $Current.title -cne $Title
  $TitleArguments = @{}
  if ($NeedsTitleUpdate) {
    $AuthorToken = Get-WinGetPendingPackageAuthorToken -Author $Current.user.login
    if ($null -ne $AuthorToken) { $TitleArguments.Token = $AuthorToken }
  }
  # Content and title are separate GitHub writes. A retry after a title failure
  # must repair that title without committing the same manifests again.
  $NeedsManifestCommit = -not (Test-WinGetPendingPackageContentEquality -Reference $Reference -Content $Content -PackageVersion $PackageVersion -RootPath $RootPath)
  if ($NeedsManifestCommit) {
    if ($Reference.RepoBranch -ceq $Current.head.repo.default_branch) { throw 'Refusing to update a pending PR on its repository default branch. Use NewPullRequest instead.' }
    $Repository = Invoke-GitHubApi -Uri "https://api.github.com/repos/$($Reference.RepoOwner)/$($Reference.RepoName)" -ErrorAction Stop
    if (-not $Repository.permissions.push) { throw "The token cannot push to $($Reference.RepoOwner)/$($Reference.RepoName). Use NewPullRequest or grant explicit branch write access." }

    $Identifier = $Reference.Manifest.PackageIdentifier
    $Prefix = Get-WinGetGitHubPackagePath -PackageIdentifier $Identifier -PackageVersion $PackageVersion -RootPath $RootPath
    $Additions = @(ConvertTo-WinGetGitHubManifestFileAddition -Manifest $Content -PackageIdentifier $Identifier -Prefix $Prefix)
    $RemovePaths = @($Reference.Paths | Where-Object { $_ -cnotin $Additions.path })
    # A unique headline distinguishes our own recovered mutation from a
    # concurrent author's commit when an HTTP response is lost.
    $CommitMessage = "${Title} (pending PR #${Number}; $([guid]::NewGuid()))"
    $null = Add-WinGetGitHubManifests -PackageIdentifier $Identifier -PackageVersion $PackageVersion -RepoOwner $Reference.RepoOwner -RepoName $Reference.RepoName -RepoBranch $Reference.RepoBranch -RepoSha $Reference.HeadSha -RootPath $RootPath -Manifest $Content -RemovePath $RemovePaths -RequireUnchangedHead -CommitMessage $CommitMessage
  }
  if ($NeedsTitleUpdate) {
    try {
      $null = Set-WinGetGitHubPullRequestTitle -PullRequestNumber $Number -Title $Title -RepoOwner $RepoOwner -RepoName $RepoName @TitleArguments -ErrorAction Stop
    } catch {
      # Keep the committed manifests. Report the partial outcome so a rerun
      # retries only the title rather than treating the override as complete.
      $Details = $TitleArguments.ContainsKey('Token') ? 'Check the configured author token and its PR-edit permissions or GitHub API access' : [string]$_
      throw "PR #${Number} contains the requested manifests, but updating its title failed: ${Details}. Rerun to retry the title without another manifest commit."
    }
  }
  if ($NeedsManifestCommit) {
    $Task.Log("Updated pending-package PR #${Number} to version ${PackageVersion}: $($Current.html_url)", 'Info')
  } else {
    $Task.Log("Pending PR #${Number} already contains these manifests. Its title is current, and no new commit or PR was needed: $($Current.html_url)", 'Info')
  }
}

Export-ModuleMember -Function Get-WinGetPendingPackageReference, Test-WinGetPendingPackageContentEquality, Update-WinGetPendingPackagePullRequest
