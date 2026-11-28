# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

# The keywords GitHub documents as the ones that close an issue, so that no spelling is invented here.
# https://docs.github.com/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue
$DumplingsWinGetGitHubIssueClosingKeywords = [string[]]@('close', 'closes', 'closed', 'fix', 'fixes', 'fixed', 'resolve', 'resolves', 'resolved')

function Get-WinGetGitHubPackagePath {
  <#
  .SYNOPSIS
    Get the relative path of a package, a version of the package, or a manifest of the version of the package
  .DESCRIPTION
    Get the relative path of
    - a package, or
    - a version, if the version parameter is provided, or
    - a version/installer manifest, if the version parameter is provided and the manifest type parameter is set to version/installer, or
    - a locale manifest, if the version parameter is provided, the manifest type parameter is set to locale, and the locale parameter is provided.
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version fo the package
  .PARAMETER ManifestType
    The type of the manifest
  .PARAMETER Locale
    The locale of the locale manifest
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .EXAMPLE
    PS> Get-WinGetGitHubPackagePath -PackageIdentifier 'SpecterShell.Dumplings'

    s/SpecterShell/Dumplings
  .EXAMPLE
    PS> Get-WinGetGitHubPackagePath -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.14.514'

    s/SpecterShell/Dumplings/1.14.514
  .EXAMPLE
    PS> Get-WinGetGitHubPackagePath -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.14.514' -ManifestType 'installer'

    s/SpecterShell/Dumplings/1.14.514/SpecterShell.Dumplings.installer.yaml
  .EXAMPLE
    PS> Get-WinGetGitHubPackagePath -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.14.514' -ManifestType 'locale' -Locale 'en-US'

    s/SpecterShell/Dumplings/1.14.514/SpecterShell.Dumplings.locale.en-US.yaml
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The identifier of the package')]
    # TODO: Fetch validation pattern from schemas
    [ValidatePattern('^[^\.\s\\/:\*\?\"<>\|\x01-\x1f]{1,32}(\.[^\.\s\\/:\*\?\"<>\|\x01-\x1f]{1,32}){1,7}$')]
    [ValidateLength(0, 128)]
    [string]$PackageIdentifier,
    [Parameter(Position = 1, HelpMessage = 'The version of the package')]
    [ValidatePattern('^[^\\/:\*\?\"<>\|\x01-\x1f]+$')]
    [ValidateLength(0, 128)]
    [string]$PackageVersion,
    [Parameter(Position = 2, HelpMessage = 'The type of the manifest')]
    [ValidateSet('version', 'installer', 'locale')]
    [string]$ManifestType,
    [Parameter(Position = 3, HelpMessage = 'The locale of the locale manifest')]
    [ValidatePattern('^([a-zA-Z]{2,3}|[iI]-[a-zA-Z]+|[xX]-[a-zA-Z]{1,8})(-[a-zA-Z]{1,8})*$')]
    [ValidateLength(0, 20)]
    [string]$Locale,
    [Parameter(HelpMessage = 'The path to the root folder of the manifests repository')]
    [ValidateNotNull()]
    [string]$RootPath = ''
  )

  process {
    # s
    $Path = $RootPath ? "${RootPath}/$($PackageIdentifier.ToLower().Chars(0))" : $PackageIdentifier.ToLower().Chars(0)

    # s/SpecterShell/Dumplings
    $PackageIdentifier.Split('.').ForEach({ $Path = "${Path}/${_}" })

    # If the package version is provided, append it to the path
    # s/SpecterShell/Dumplings/1.14.514
    if ($PackageVersion) {
      $Path = "${Path}/${PackageVersion}"

      # If the manifest type is provided, append the manifest file name to the path
      if ($ManifestType) {
        switch ($ManifestType) {
          # s/SpecterShell/Dumplings/1.14.514/SpecterShell.Dumplings.yaml
          'version' { $Path = "${Path}/${PackageIdentifier}.yaml" }
          # s/SpecterShell/Dumplings/1.14.514/SpecterShell.Dumplings.installer.yaml
          'installer' { $Path = "${Path}/${PackageIdentifier}.installer.yaml" }
          # s/SpecterShell/Dumplings/1.14.514/SpecterShell.Dumplings.locale.en-US.yaml
          'locale' {
            if (-not $Locale) { throw 'Locale must be provided when manifest type is locale' }
            $Path = "${Path}/${PackageIdentifier}.locale.${Locale}.yaml"
          }
        }
      }
    }

    return $Path
  }
}

function Get-WinGetGitHubPackageVersion {
  <#
  .SYNOPSIS
    Get the available versions of a package from the remote repository
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch name of the repository
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER AllowMissing
    Return no versions for HTTP 404. Authentication and transport failures still throw.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [switch]$AllowMissing
  )

  process {
    $Prefix = Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -RootPath $RootPath

    # https://docs.github.com/rest/git/trees#get-a-tree
    try {
      $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/trees/${RepoBranch}:${Prefix}?recursive=true"
    } catch {
      # The GitHub proxy retains the original HTTP exception as its inner exception.
      # Only a confirmed missing path may activate the pending-package fallback.
      for ($Exception = $_.Exception; $Exception; $Exception = $Exception.InnerException) {
        $ResponseProperty = $Exception.PSObject.Properties['Response']
        $StatusProperty = $Exception.PSObject.Properties['StatusCode']
        $Status = if ($ResponseProperty -and $ResponseProperty.Value) { $ResponseProperty.Value.StatusCode } elseif ($StatusProperty) { $StatusProperty.Value }
        if ($AllowMissing -and $null -ne $Status -and [int]$Status -eq 404) { return }
      }
      throw
    }
    $Response.tree |
      ForEach-Object -Process { if ($_.type -eq 'blob' -and $_.path -match "^([^/]+)/$([regex]::Escape($PackageIdentifier))\.yaml$") { $Matches[1] } } |
      Sort-Object -Property { [WinGetVersion]$_ } -Stable
  }
}

function Get-WinGetGitHubPackageAncestorPath {
  <#
  .SYNOPSIS
    Get the folders that contain a package, from the closest parent up to the first-character folder
  .DESCRIPTION
    Get the folders that contain a package in the manifests repository, ordered from the closest parent
    up to the first-character folder. The package folder itself is not returned.
    A package identifier of SpecterShell.Dumplings yields manifests/s/SpecterShell and manifests/s when
    the root path is manifests.
    Submission uses these folders when the package folder has no history in the reference branch.
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .EXAMPLE
    PS> Get-WinGetGitHubPackageAncestorPath -PackageIdentifier 'SpecterShell.Dumplings' -RootPath 'manifests'

    manifests/s/SpecterShell
    manifests/s
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(HelpMessage = 'The path to the root folder of the manifests repository')]
    [ValidateNotNull()]
    [string]$RootPath = ''
  )

  process {
    # s, SpecterShell, Dumplings
    $Segments = @([string]$PackageIdentifier.ToLower().Chars(0)) + @($PackageIdentifier.Split('.'))

    # s/SpecterShell, then s
    for ($Length = $Segments.Count - 1; $Length -ge 1; $Length--) {
      $Path = $Segments[0..($Length - 1)] -join '/'
      $RootPath ? "${RootPath}/${Path}" : $Path
    }
  }
}

function Get-WinGetGitHubCommitPage {
  <#
  .SYNOPSIS
    Get one page of the commit listing of a repository path
  .DESCRIPTION
    Get one page of the commit listing of a repository path together with the last page number reported by
    the response Link header. Reading the last page lets a caller reach the oldest commit of a path without
    walking every page, because GitHub lists commits from the newest to the oldest.
  .PARAMETER Uri
    The commit listing URI of one page
  .OUTPUTS
    An object with Commits, the commits of that page, LastPage, the number of the last page, and
    HasMorePages, which indicates that GitHub reported another page without reporting the last one.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The commit listing URI of one page')]
    [string]$Uri
  )

  process {
    # GitHub reports the page count only in the Link response header, so the request asks for response
    # headers and reads them through Get-GitHubApiResponseHeader.
    $Commits = @(Invoke-GitHubApi -Uri $Uri -ResponseHeadersVariable Headers)
    $Link = Get-GitHubApiResponseHeader -Name 'Link'

    [pscustomobject]@{
      Commits      = $Commits
      LastPage     = ConvertFrom-GitHubLinkHeader -Link $Link
      HasMorePages = [bool]($Link -match 'rel="next"')
    }
  }
}

function Get-WinGetGitHubHistoryAnchor {
  <#
  .SYNOPSIS
    Get the newest commit of a branch at or before a date
  .DESCRIPTION
    Get the newest commit reachable from the given branch at or before the given date.
    The listing of the whole repository paginates to its first commit even when the listing of a single
    path does not, so a commit read from it narrows a path listing to an early date without walking the
    history of the path.
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch, tag, or commit SHA whose history is searched
  .PARAMETER Until
    The date the commit is at or before
  .OUTPUTS
    The commit object reported by GitHub, or nothing when the branch has no commit at or before that date.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(Mandatory, HelpMessage = 'The date the commit is at or before')]
    [datetime]$Until
  )

  process {
    # https://docs.github.com/rest/commits/commits#list-commits
    $Date = $Until.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $Uri = "https://api.github.com/repos/${RepoOwner}/${RepoName}/commits?sha=$([Uri]::EscapeDataString($RepoBranch))&per_page=1&until=${Date}"
    foreach ($Commit in (Invoke-GitHubApi -Uri $Uri)) { return $Commit }
  }
}

function Get-WinGetGitHubOldestPathCommitPage {
  <#
  .SYNOPSIS
    Get the page of a path commit listing that holds the oldest commit
  .DESCRIPTION
    Get the page of the commit listing of a path that holds the commit which established the path.
    GitHub lists commits from the newest to the oldest and reports the number of the last page in the
    response Link header, so the oldest commit of a path with a paginated history reads with two requests.
    GitHub reports no last page and refuses deeper pages once a path has more commits than it paginates,
    which happens for the first-character folders of the manifests repository because one repository-wide
    commit created all of them when it partitioned the manifests by publisher
    (https://github.com/microsoft/winget-pkgs/issues/8900). The listing is then narrowed with commits that
    move towards the commit which established the path. The oldest commit of every narrowed listing is
    still the commit which established the path, so the first listing that GitHub pages is already exact,
    and a path that does not exist yet at a narrowed commit started later, which moves the lower bound of
    the search forward.
  .PARAMETER Path
    The relative path whose history is searched
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch, tag, or commit SHA whose history is searched
  .OUTPUTS
    The page whose last entry is the oldest commit of the path. The newest page is returned when the
    history cannot be narrowed.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The relative path whose history is searched')]
    [string]$Path,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch
  )

  process {
    # https://docs.github.com/rest/commits/commits#list-commits
    $Query = "https://api.github.com/repos/${RepoOwner}/${RepoName}/commits?path=$([Uri]::EscapeDataString($Path))&per_page=100&sha="
    $Uri = "${Query}$([Uri]::EscapeDataString($RepoBranch))"

    $Page = Get-WinGetGitHubCommitPage -Uri "${Uri}&page=1"
    if ($Page.LastPage -gt 1) { return Get-WinGetGitHubCommitPage -Uri "${Uri}&page=$($Page.LastPage)" }
    if (-not $Page.HasMorePages -or -not $Page.Commits.Count) { return $Page }

    # The path has more commits than GitHub paginates, so the listing is narrowed by date. Each narrowed
    # listing starts at a commit anchor, which keeps the request inside a listing GitHub can page, and
    # the newest commit of the path bounds the search from above. The oldest commit of any narrowed listing
    # is still the commit that established the path, so the first listing GitHub can page is already exact.
    $Upper = [datetime]$Page.Commits[0].commit.committer.date
    $Lower = $Upper.AddYears(-10)
    for ($Step = 0; $Step -lt 16 -and ($Upper - $Lower) -gt [timespan]'1.00:00:00'; $Step++) {
      $Middle = $Lower.AddTicks([long](($Upper - $Lower).Ticks / 2))
      $Anchor = Get-WinGetGitHubHistoryAnchor -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch -Until $Middle
      if (-not $Anchor) {
        # The repository has no commit that early, so the path cannot be older than the middle date.
        $Lower = $Middle
        continue
      }
      $AnchoredUri = "${Query}$($Anchor.sha)"
      $Anchored = Get-WinGetGitHubCommitPage -Uri "${AnchoredUri}&page=1"
      if (-not $Anchored.Commits.Count) {
        # The path does not exist yet at the anchor, so the commit which established it is newer.
        $Lower = $Middle
        continue
      }
      if ($Anchored.LastPage -gt 1) { return Get-WinGetGitHubCommitPage -Uri "${AnchoredUri}&page=$($Anchored.LastPage)" }
      if (-not $Anchored.HasMorePages) { return $Anchored }
      # The narrowed listing is still deeper than GitHub pages, so the path was established before it.
      $Upper = $Middle
    }

    Write-Verbose "The history of ${Path} could not be narrowed to the commit that established it, so its newest commit is used instead."
    $Page
  }
}

function Get-WinGetGitHubPathCommit {
  <#
  .SYNOPSIS
    Get the newest or the oldest commit that changed a path in the remote repository
  .DESCRIPTION
    Get a commit reachable from the given branch that changed any file below the given path.
    GitHub lists commits from the newest to the oldest. The newest commit is the first entry of that
    listing, while the oldest commit, which is the commit that established the path, is the last entry
    of the last page.
    A path with more commits than GitHub paginates has no reported last page, so the listing is narrowed
    by date until it fits in a paginated listing and the oldest commit of that listing is read.
  .PARAMETER Path
    The relative path whose history is searched
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch, tag, or commit SHA whose history is searched
  .PARAMETER Oldest
    Return the oldest commit instead of the newest commit
  .OUTPUTS
    The commit object reported by GitHub, or nothing when the path has no commit in that history.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The relative path whose history is searched')]
    [string]$Path,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(HelpMessage = 'Indicates that the oldest commit is returned instead of the newest commit')]
    [switch]$Oldest
  )

  process {
    # https://docs.github.com/rest/commits/commits#list-commits
    $Uri = "https://api.github.com/repos/${RepoOwner}/${RepoName}/commits?path=$([Uri]::EscapeDataString($Path))&sha=$([Uri]::EscapeDataString($RepoBranch))"

    if (-not $Oldest) {
      foreach ($Commit in (Get-WinGetGitHubCommitPage -Uri "${Uri}&per_page=1").Commits) { return $Commit }
      return
    }

    # The page lists commits from the newest to the oldest, so the last entry is the oldest commit.
    $Page = Get-WinGetGitHubOldestPathCommitPage -Path $Path -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch
    if ($Page.Commits.Count) { return $Page.Commits[-1] }
  }
}
function Get-WinGetGitHubSubmissionCommit {
  <#
  .SYNOPSIS
    Get the commit that submission bases the candidate branch of a package on
  .DESCRIPTION
    Get the commit reachable from the given branch whose tree holds everything the submission reads
    and writes, so a candidate branch created at it carries only the manifest changes of the package.
    A version directory that has history is a version that is already published and is rewritten in
    place, so the newest commit of that version directory applies. A version directory without history
    is a new version that is modeled after the package, so the newest commit of the package directory
    applies. A package directory without history was never submitted, so the closest folder that does
    have history supplies the commit that established it, walking from the publisher folder up to the
    first-character folder; the newest of those creation commits is the commit of the closest folder
    that exists. A first-character folder has more history than GitHub paginates in one listing because
    a single commit created all of them when the manifests were partitioned by publisher, so the commit
    that established it is resolved by narrowing that listing by date.
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version of the package that the submission writes
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch, tag, or commit SHA whose history is searched
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .OUTPUTS
    The commit object reported by GitHub, or nothing when neither the version, the package, nor a
    containing folder has a commit in that history. The Path property reports the folder the commit
    belongs to.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(Mandatory, HelpMessage = 'The version of the package that the submission writes')]
    [string]$PackageVersion,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath
  )

  process {
    $VersionPath = Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath
    $Commit = Get-WinGetGitHubPathCommit -Path $VersionPath -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch
    if ($Commit) { return $Commit | Add-Member -NotePropertyName 'Path' -NotePropertyValue $VersionPath -Force -PassThru }

    $Path = Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -RootPath $RootPath
    $Commit = Get-WinGetGitHubPathCommit -Path $Path -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch

    if (-not $Commit) {
      foreach ($AncestorPath in Get-WinGetGitHubPackageAncestorPath -PackageIdentifier $PackageIdentifier -RootPath $RootPath) {
        $Commit = Get-WinGetGitHubPathCommit -Path $AncestorPath -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch -Oldest
        if ($Commit) {
          $Path = $AncestorPath
          break
        }
      }
    }

    if ($Commit) { return $Commit | Add-Member -NotePropertyName 'Path' -NotePropertyValue $Path -Force -PassThru }
  }
}

function Get-WinGetGitHubManifestVersionCommit {
  <#
  .SYNOPSIS
    Get a commit of the authoring tool that already declares a manifest version
  .DESCRIPTION
    Get the newest commit of the authoring tool that declares the given manifest version or a newer one.
    A submission that writes manifests with a newer manifest version than the reference has to be based
    at or after the commit that made that version current in the manifests repository, so the candidate
    branch and the repository describe the same schema version.
    The version is read from the authoring tool itself instead of matched in commit messages, because the
    message wording is not part of the tool's contract and a renamed or abbreviated message silently based
    the candidate branch on a commit that predates the version change. Every commit of the tool is a
    descendant of the commit that introduced the version it declares, so the newest commit already
    satisfies the requirement when it declares the given version or a newer one.
    A tool that declares an older version has not received that version yet, and nothing is returned.
  .PARAMETER ManifestVersion
    The manifest version that the candidate branch has to support
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch, tag, or commit SHA whose history is searched
  .PARAMETER ToolsPath
    The path of the authoring tool that declares the manifest version
  .OUTPUTS
    The commit object reported by GitHub, or nothing when the tool does not declare the given version or
    a newer one.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The manifest version that the candidate branch has to support')]
    [string]$ManifestVersion,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(HelpMessage = 'The path of the authoring tool that declares the manifest version')]
    [string]$ToolsPath = 'Tools/YamlCreate.ps1'
  )

  process {
    $Target = [version]::new()
    if (-not [version]::TryParse($ManifestVersion, [ref]$Target)) { return }

    $Commit = Get-WinGetGitHubPathCommit -Path $ToolsPath -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch
    if (-not $Commit) { return }

    # https://docs.github.com/rest/repos/contents#get-repository-content
    $Content = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/contents/${ToolsPath}?ref=$([Uri]::EscapeDataString([string]$Commit.sha))"
    $Text = [string]$Content.content | ConvertFrom-Base64
    # The tool assigns its manifest version once as a literal, so the declarations of settings overrides
    # and of a version comparison cannot be mistaken for the version it writes.
    $Pattern = '(?m)^\s*\$ManifestVersion\s*=\s*''(?<Version>[^'']+)'''
    $Declared = [version]::new()
    if (-not [version]::TryParse([regex]::Match($Text, $Pattern).Groups['Version'].Value, [ref]$Declared)) { return }
    if ($Declared -lt $Target) { return }

    return $Commit
  }
}

function Get-WinGetGitHubManifests {
  <#
  .SYNOPSIS
    Get the available manifests of a package version from the remote repository
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch name of the repository
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path
  )

  process {
    $Prefix = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : (Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath)

    <#
    # https://docs.github.com/rest/repos/contents#get-repository-content
    $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/${Prefix}?ref=${RepoBranch}"
    if ($Response -isnot [System.Collections.IEnumerable]) { throw "${Prefix} is not a directory" }
    $Response | Where-Object -FilterScript {
      $_.type -eq 'file' -and (
        $_.name -ceq "${PackageIdentifier}.yaml" -or
        $_.name -ceq "${PackageIdentifier}.installer.yaml" -or
        $_.name -clike "${PackageIdentifier}.locale.*.yaml"
      )
    }
    #>

    # https://docs.github.com/rest/git/trees#get-a-tree
    $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/trees/${RepoBranch}:${Prefix}"
    $Response.tree | Where-Object -FilterScript {
      $_.type -eq 'blob' -and (
        $_.path -ceq "${PackageIdentifier}.yaml" -or
        $_.path -ceq "${PackageIdentifier}.installer.yaml" -or
        $_.path -clike "${PackageIdentifier}.locale.*.yaml"
      )
    }
  }
}

function Read-WinGetGitHubManifestContent {
  <#
  .SYNOPSIS
    Read the content of a manifest file from the remote repository
  .PARAMETER Path
    The path to the manifest
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch name of the repository
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', ValueFromPipeline, Mandatory, HelpMessage = 'The path to the manifest')]
    [string]$Path,
    [Parameter(ParameterSetName = 'Uri', ValueFromPipeline, ValueFromPipelineByPropertyName, DontShow, Mandatory, HelpMessage = 'The URI to the manifest')]
    [Alias('Url')]
    [string]$Uri,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch
  )

  process {
    # https://docs.github.com/rest/repos/contents#get-repository-content
    $Response = $PSCmdlet.ParameterSetName -eq 'Uri' ? (Invoke-GitHubApi -Uri $Uri) : (Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/contents/${Path}?ref=${RepoBranch}")
    return $Response.content.Replace("`n", '') | ConvertFrom-Base64
  }
}

function Read-WinGetGitHubManifests {
  <#
  .SYNOPSIS
    Read the manifests for a package from the remote repository
  .DESCRIPTION
    Read the installer, locale and version manifests for a package from the remote repository using the provided package identifier.
  .PARAMETER PackageIdentifier
    The package identifier of the manifest
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch name of the repository
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The package identifier of the manifest')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path
  )

  $Prefix = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : (Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath)

  $Response = Invoke-GitHubApi -Uri 'https://api.github.com/graphql' -Method Post -Body @{
    query = @"
{
  repository(owner: "${RepoOwner}", name: "${RepoName}") {
    object(expression: "${RepoBranch}:${Prefix}") {
      ... on Tree {
        entries {
          name
          type
          object {
            ... on Blob {
              text
            }
          }
        }
      }
    }
  }
}
"@
  }

  $ManifestItems = $Response.data.repository.object.entries.Where({ $_.type -eq 'blob' })

  # Process mandatory version manifest. The number of version manifests must be exactly one.
  $VersionManifestItem = $ManifestItems.Where({ $_.name -ceq "${PackageIdentifier}.yaml" })
  if ($VersionManifestItem.Count -gt 1) { throw "Multiple version manifests found for package '$PackageIdentifier'. Please ensure there is only one version manifest." }
  elseif ($VersionManifestItem.Count -eq 0) { throw "No version manifest found for package '$PackageIdentifier'. Please ensure the version manifest exists." }
  else { $VersionManifestContent = $VersionManifestItem[0].object.text }

  # Process optional installer manifest. The number of installer manifests must be zero or one.
  $InstallerManifestContent = $null
  $InstallerManifestItem = $ManifestItems.Where({ $_.name -ceq "${PackageIdentifier}.installer.yaml" })
  if ($InstallerManifestItem.Count -gt 1) { throw "Multiple installer manifests found for package '$PackageIdentifier'. Please ensure there is only one installer manifest." }
  elseif ($InstallerManifestItem.Count -eq 1) { $InstallerManifestContent = $InstallerManifestItem[0].object.text }

  # Process optional locale manifests. The number of locale manifests can be zero or more.
  $LocaleManifestContent = [ordered]@{}
  $ManifestItems | ForEach-Object -Process {
    if ($_.name -match "^$([regex]::Escape($PackageIdentifier))\.locale\.(.+)\.yaml$") {
      $LocaleManifestContent[$Matches[1]] = $_.object.text
    }
  }

  return [ordered]@{
    Version   = $VersionManifestContent
    Installer = $InstallerManifestContent
    Locale    = $LocaleManifestContent
  }
}

function Get-WinGetGitHubBranch {
  <#
  .SYNOPSIS
    Get the branch of a GitHub repository
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch name of the repository
  .PARAMETER RepoRef
    The reference of the repository. Format: "ref/heads/branch" or "ref/tags/tag"
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(ParameterSetName = 'Branch', Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(ParameterSetName = 'Ref', Mandatory, HelpMessage = 'The reference of the repository. Format: "ref/heads/branch" or "ref/tags/tag"')]
    [string]$RepoRef
  )

  # Get the branches of the repository
  $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/$($PSCmdlet.ParameterSetName -eq 'Ref' ? $RepoRef : "ref/heads/${RepoBranch}")"

  return $Response
}

function Get-WinGetGitHubComparison {
  <#
  .SYNOPSIS
    Compare two Git references through the GitHub compare API.
  .DESCRIPTION
    Returns the commit and file delta from Base to Head. A ref may be qualified
    with an owner (for example, "fork-owner:feature-branch") when comparing a
    branch from a fork against the upstream repository.
  .PARAMETER Base
    Base branch, tag, commit SHA, or owner-qualified Git reference.
  .PARAMETER Head
    Head branch, tag, commit SHA, or owner-qualified Git reference.
  .PARAMETER RepoOwner
    Owner of the repository whose fork network contains both references.
  .PARAMETER RepoName
    Name of the repository whose fork network contains both references.
  .OUTPUTS
    The GitHub comparison response, including status, ahead_by, and files.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The base Git reference')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Base,
    [Parameter(Mandatory, HelpMessage = 'The head Git reference')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Head,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoName
  )

  # Encode each ref independently so the three-dot comparison delimiter remains
  # part of the endpoint while slashes and owner qualifiers stay unambiguous.
  $BaseReference = [Uri]::EscapeDataString($Base)
  $HeadReference = [Uri]::EscapeDataString($Head)
  return (Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/compare/${BaseReference}...${HeadReference}")
}

function New-WinGetGitHubBranch {
  <#
  .SYNOPSIS
    Create a new branch in a GitHub repository
  .PARAMETER Name
    The name of the new branch to create
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The source branch of the repository from which the new branch will be created
  .PARAMETER RepoRef
    The reference of the source branch from which the new branch will be created. Format: "refs/heads/branch" or "refs/tags/tag"
  .PARAMETER SourceSha
    Optional immutable source commit captured when reading reference manifests.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The name of the new branch to create')]
    [string]$Name,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(ParameterSetName = 'Branch', Mandatory, HelpMessage = 'The source branch of the repository from which the new branch will be created')]
    [string]$RepoBranch,
    [Parameter(ParameterSetName = 'Ref', Mandatory, HelpMessage = 'The reference of the source branch from which the new branch will be created. Format: "refs/heads/branch" or "refs/tags/tag"')]
    [string]$RepoRef,
    [ValidatePattern('^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$')][string]$SourceSha
  )

  # Get the reference of the source branch
  if (-not $SourceSha) {
    $SourceBranch = Get-WinGetGitHubBranch -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch
    $SourceSha = $SourceBranch.object.sha
  }

  # Create the new branch
  $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/refs" -Method Post -Body @{
    ref = $PSCmdlet.ParameterSetName -eq 'Ref' ? $RepoRef : "refs/heads/${Name}"
    sha = $SourceSha
  }

  return $Response
}

function Remove-WinGetGitHubBranch {
  <#
  .SYNOPSIS
    Delete a branch reference from a GitHub repository.
  .PARAMETER Name
    Branch name to delete.
  .PARAMETER RepoOwner
    Owner of the repository.
  .PARAMETER RepoName
    Name of the repository.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The branch name to delete')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Name,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoName
  )

  $EncodedName = [Uri]::EscapeDataString($Name)
  if ($PSCmdlet.ShouldProcess("${RepoOwner}/${RepoName}:refs/heads/${Name}", 'Delete GitHub branch')) {
    return (Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/refs/heads/${EncodedName}" -Method Delete)
  }
}

function Assert-WinGetGitHubGraphQLCommit {
  <#
  .SYNOPSIS
    Surface GraphQL errors and return the created commit OID
  .DESCRIPTION
    GitHub GraphQL reports failures as HTTP 200 responses with an errors
    collection and a null payload instead of a failing status code. Reading
    the commit OID without checking would silently treat a rejected commit as
    created, leaving the branch unchanged.
  .PARAMETER Response
    The GraphQL response returned by Invoke-GitHubApi
  .PARAMETER Operation
    The operation description used in error messages
  .OUTPUTS
    The OID of the created commit.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The GraphQL response returned by Invoke-GitHubApi')]
    $Response,
    [Parameter(Mandatory, HelpMessage = 'The operation description used in error messages')]
    [string]$Operation
  )

  $ErrorsProperty = $Response.PSObject.Properties['errors']
  if ($null -ne $ErrorsProperty -and @($ErrorsProperty.Value).Count -gt 0) {
    $Messages = @($ErrorsProperty.Value | ForEach-Object -Process { [string]$_.message })
    throw "GitHub GraphQL rejected ${Operation}: $($Messages -join '; ')"
  }

  $CommitOid = [string]$Response.data.createCommitOnBranch.commit.oid
  if ([string]::IsNullOrWhiteSpace($CommitOid)) { throw "GitHub GraphQL did not return a commit for ${Operation}." }
  return $CommitOid
}

function Invoke-WinGetGitHubCommitMutation {
  <#
  .SYNOPSIS
    Create one commit on a GitHub branch with optimistic-head reconciliation.
  .DESCRIPTION
    GitHub's createCommitOnBranch mutation is not idempotent. An HTTP client
    retry can replay a mutation that GitHub already accepted, causing the
    second request to fail because expectedHeadOid now points at the parent of
    the newly created commit. This helper disables implicit HTTP retries and
    explicitly reconciles the branch after an ambiguous failure.

    If the branch advanced to a commit with the requested message and attempted
    head as its sole parent, the first mutation succeeded and that commit OID is
    returned. Otherwise, the mutation is retried against the observed branch
    head. This is safe for Dumplings' task-specific submission branches and
    avoids both duplicate commits and stale-head failures.
  .PARAMETER RepoOwner
    The owner of the repository containing the branch.
  .PARAMETER RepoName
    The name of the repository containing the branch.
  .PARAMETER RepoBranch
    The branch to update.
  .PARAMETER ExpectedHeadOid
    The branch head expected by the first mutation attempt.
  .PARAMETER CommitMessage
    The commit headline. It is also used to identify a mutation that succeeded
    before its response was lost.
  .PARAMETER FileChanges
    GraphQL fileChanges input containing additions and/or deletions.
  .PARAMETER Operation
    Human-readable operation description used in diagnostics.
  .PARAMETER MaximumAttempts
    Maximum number of explicit mutation attempts.
  .PARAMETER RequireUnchangedHead
    Reject an unrelated branch advance instead of replaying changes onto it. Used for existing PR branches.
  .OUTPUTS
    The OID of the created or reconciled commit.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch to update')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoBranch,
    [Parameter(Mandatory, HelpMessage = 'The expected branch head OID')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$ExpectedHeadOid,
    [Parameter(Mandatory, HelpMessage = 'The commit headline')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$CommitMessage,
    [Parameter(Mandatory, HelpMessage = 'The GraphQL fileChanges input')]
    [System.Collections.IDictionary]$FileChanges,
    [Parameter(Mandatory, HelpMessage = 'The operation description used in diagnostics')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Operation,
    [Parameter(HelpMessage = 'The maximum number of explicit mutation attempts')]
    [ValidateRange(1, 10)]
    [int]$MaximumAttempts = 3,
    [switch]$RequireUnchangedHead
  )

  $Mutation = @'
mutation CreateCommitOnBranch($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) {
    commit {
      oid
    }
  }
}
'@
  $AttemptHeadOid = $ExpectedHeadOid

  foreach ($Attempt in 1..$MaximumAttempts) {
    try {
      # Never let Invoke-RestMethod replay this non-idempotent mutation. Any
      # retry must first inspect the branch to determine whether GitHub applied
      # the preceding request.
      $Response = Invoke-GitHubApi -Uri 'https://api.github.com/graphql' -Method Post -MaximumRetryCount 0 -Body @{
        query     = $Mutation
        variables = @{
          input = @{
            branch          = @{
              repositoryNameWithOwner = "${RepoOwner}/${RepoName}"
              branchName              = $RepoBranch
            }
            message         = @{ headline = $CommitMessage }
            fileChanges     = $FileChanges
            expectedHeadOid = $AttemptHeadOid
          }
        }
      }
      return Assert-WinGetGitHubGraphQLCommit -Response $Response -Operation $Operation
    } catch {
      $MutationError = $_
    }

    try {
      # A failed client request can still have committed server-side. Read the
      # authoritative branch head before deciding whether another POST is safe.
      $CurrentHeadOid = [string](Get-WinGetGitHubBranch -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch).object.sha
      if ([string]::IsNullOrWhiteSpace($CurrentHeadOid)) {
        throw "GitHub did not return the current head of ${RepoOwner}/${RepoName}:${RepoBranch}."
      }

      if ($CurrentHeadOid -cne $AttemptHeadOid) {
        $EncodedHeadOid = [Uri]::EscapeDataString($CurrentHeadOid)
        $CurrentCommit = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/commits/${EncodedHeadOid}" -MaximumRetryCount 0
        $Parents = @($CurrentCommit.parents)
        $IsRecoveredCommit = $Parents.Count -eq 1 -and
        [string]$Parents[0].sha -ceq $AttemptHeadOid -and
        [string]$CurrentCommit.message -ceq $CommitMessage

        if ($IsRecoveredCommit) {
          Write-Verbose "Recovered ${Operation} at ${CurrentHeadOid}; GitHub advanced the branch before the mutation response was received."
          return $CurrentHeadOid
        }

        if ($RequireUnchangedHead) {
          throw 'The referenced pull-request branch advanced. Refusing to overwrite concurrent changes; rerun against its new head.'
        }

        # Another operation advanced this task branch. Preserve that work and
        # retry the requested file changes against the actual current head.
        $AttemptHeadOid = $CurrentHeadOid
      }
    } catch {
      throw "Failed to reconcile ${Operation} after an ambiguous GitHub response. Mutation error: $MutationError Reconciliation error: $_"
    }

    if ($Attempt -eq $MaximumAttempts) {
      throw "Failed to create ${Operation} after ${MaximumAttempts} attempts: $MutationError"
    }

    Start-Sleep -Seconds 1
  }
}

function ConvertTo-WinGetGitHubManifestFileAddition {
  <#
  .SYNOPSIS
    Build deterministic GraphQL file additions from a raw manifest bundle.
  .PARAMETER Manifest
    Bundle containing Version, Installer, and locale YAML strings.
  .PARAMETER PackageIdentifier
    Identifier used for physical manifest filenames.
  .PARAMETER Prefix
    Repository-relative version directory, without a trailing slash.
  .OUTPUTS
    File additions with repository paths and base64-encoded UTF-8, LF-normalized content.
  #>
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Manifest,
    [Parameter(Mandatory)][string]$PackageIdentifier,
    [Parameter(Mandatory)][string]$Prefix
  )

  $Manifests = [ordered]@{}
  if (-not $Manifest['Version']) { throw 'The version manifest is null or empty.' }
  $Manifests["${PackageIdentifier}.yaml"] = $Manifest['Version']
  if ($Manifest['Installer']) { $Manifests["${PackageIdentifier}.installer.yaml"] = $Manifest['Installer'] }
  if ($Manifest['Locale']) {
    foreach ($Entry in $Manifest['Locale'].GetEnumerator()) { $Manifests["${PackageIdentifier}.locale.$($Entry.Key).yaml"] = $Entry.Value }
  }
  foreach ($Entry in $Manifests.GetEnumerator()) {
    [ordered]@{
      path     = "${Prefix}/$($Entry.Key)"
      contents = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Entry.Value.ReplaceLineEndings("`n")))
    }
  }
}

function Add-WinGetGitHubManifests {
  <#
  .SYNOPSIS
    Add a package version to the remote repository
  .DESCRIPTION
    Add a package version to the remote repository using GitHub GraphQL API CreateCommitOnBranch mutation.
  .PARAMETER PackageIdentifier
    The package identifier of the manifest
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch name of the repository
  .PARAMETER RepoSha
    The SHA of the commit to create the new commit from
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  .PARAMETER Manifest
    The manifest(s) to add
  .PARAMETER CommitMessage
    The message of the commit
  .PARAMETER RemovePath
    Exact manifest paths under this package to delete in the same atomic commit.
  .PARAMETER RequireUnchangedHead
    Do not replay changes after an unrelated branch advance.
  .OUTPUTS
    The SHA of the commit created in the remote repository.
  #>
  [OutputType([string])]
  [CmdletBinding(DefaultParameterSetName = 'RootPath')]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The package identifier of the manifest')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(HelpMessage = 'The SHA of the commit to create the new commit from')]
    [string]$RepoSha = (Get-WinGetGitHubBranch -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch).object.sha,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path,
    [Parameter(ValueFromPipeline, Mandatory, HelpMessage = 'The manifest(s) to add')]
    [System.Collections.IDictionary[]]$Manifest,
    [Parameter(Mandatory, HelpMessage = 'The message of the commit')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$CommitMessage,
    [Parameter(ParameterSetName = 'RootPath')]
    [string[]]$RemovePath = @(),
    [switch]$RequireUnchangedHead
  )

  process {
    $Prefix = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : (Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath)

    if ($Manifest.Count -ne 1) { throw 'One raw manifest bundle is required per commit.' }
    $Additions = @(ConvertTo-WinGetGitHubManifestFileAddition -Manifest $Manifest[0] -PackageIdentifier $PackageIdentifier -Prefix $Prefix)
    $FileChanges = [ordered]@{ additions = $Additions }
    if ($RemovePath.Count) {
      $PackagePrefix = (Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -RootPath $RootPath) + '/'
      $Deletions = [Collections.Generic.List[System.Collections.IDictionary]]::new()
      foreach ($Deletion in @($RemovePath | Select-Object -Unique)) {
        if (-not $Deletion.StartsWith($PackagePrefix, [StringComparison]::Ordinal) -or $Deletion.Split('/') -contains '..' -or $Deletion.Split('/') -contains '.' -or -not $Deletion.EndsWith('.yaml', [StringComparison]::Ordinal)) {
          throw "Refusing to delete a path outside the package's manifest files: $Deletion"
        }
        if ($Deletion -cin $Additions.path) { throw "A manifest cannot be added and deleted in the same commit: $Deletion" }
        $Deletions.Add([ordered]@{ path = $Deletion })
      }
      $FileChanges.deletions = $Deletions.ToArray()
    }

    return Invoke-WinGetGitHubCommitMutation `
      -RepoOwner $RepoOwner `
      -RepoName $RepoName `
      -RepoBranch $RepoBranch `
      -ExpectedHeadOid $RepoSha `
      -CommitMessage $CommitMessage `
      -FileChanges $FileChanges `
      -RequireUnchangedHead:$RequireUnchangedHead `
      -Operation "the manifest commit for ${RepoOwner}/${RepoName}:${RepoBranch}"
  }
}

function Remove-WinGetGitHubManifests {
  <#
  .SYNOPSIS
    Remove a package version from the remote repository
  .DESCRIPTION
    Remove a package version from the remote repository using GitHub GraphQL API CreateCommitOnBranch mutation.
  .PARAMETER PackageIdentifier
    The package identifier of the manifest
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .PARAMETER RepoBranch
    The branch name of the repository
  .PARAMETER RepoSha
    The SHA of the commit to create the new commit from
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  .PARAMETER CommitMessage
    The message of the commit
  .OUTPUTS
    The SHA of the commit created in the remote repository.
  #>
  [OutputType([string])]
  [CmdletBinding(DefaultParameterSetName = 'RootPath')]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The package identifier of the manifest')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName,
    [Parameter(Mandatory, HelpMessage = 'The branch name of the repository')]
    [string]$RepoBranch,
    [Parameter(HelpMessage = 'The SHA of the commit to create the new commit from')]
    [string]$RepoSha = (Get-WinGetGitHubBranch -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch).object.sha,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path,
    [Parameter(Mandatory, HelpMessage = 'The message of the commit')]
    [string]$CommitMessage
  )

  process {
    $Prefix = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : (Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath)
    # Suppress the Boolean results so the function outputs only the commit OID.
    $null = $PSBoundParameters.Remove('RepoSha'); $null = $PSBoundParameters.Remove('CommitMessage')
    $Manifests = Get-WinGetGitHubManifests @PSBoundParameters

    $Deletions = [System.Collections.Generic.List[System.Collections.IDictionary]]::new()
    foreach ($ManifestEntry in $Manifests) {
      $Deletions.Add([ordered]@{ path = "${Prefix}/$($ManifestEntry.path)" })
    }

    return Invoke-WinGetGitHubCommitMutation `
      -RepoOwner $RepoOwner `
      -RepoName $RepoName `
      -RepoBranch $RepoBranch `
      -ExpectedHeadOid $RepoSha `
      -CommitMessage $CommitMessage `
      -FileChanges ([ordered]@{ deletions = $Deletions.ToArray() }) `
      -Operation "the manifest removal commit for ${RepoOwner}/${RepoName}:${RepoBranch}"
  }
}

function New-WinGetGitHubPullRequest {
  <#
  .SYNOPSIS
    Create a new pull request in a GitHub repository
  .PARAMETER Title
    The title of the pull request
  .PARAMETER Body
    The body content of the pull request
  .PARAMETER Head
    The head branch of the pull request (format: "branch" or "owner:branch")
  .PARAMETER Base
    The base branch of the pull request
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The title of the pull request')]
    [string]$Title,
    [Parameter(Mandatory, HelpMessage = 'The body content of the pull request')]
    [string]$Body,
    [Parameter(Mandatory, HelpMessage = 'The head branch of the pull request (format: "branch" or "owner:branch")')]
    [string]$Head,
    [Parameter(Mandatory, HelpMessage = 'The base branch of the pull request')]
    [string]$Base,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName
  )

  # Create the pull request
  $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/pulls" -Method Post -Body @{
    title = $Title
    body  = $Body
    head  = $Head
    base  = $Base
  }

  return $Response
}

function Find-WinGetGitHubPullRequest {
  <#
  .SYNOPSIS
    Find pull requests in a GitHub repository
  .PARAMETER Query
    The search query for finding pull requests
  .PARAMETER MaximumResults
    Maximum search results in the first page. The default preserves GitHub's 30-result page size.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The search query for finding pull requests')]
    [string]$Query,
    [ValidateRange(1, 100)][int]$MaximumResults = 30
  )

  return (Invoke-GitHubApi -Uri "https://api.github.com/search/issues?q=$([Uri]::EscapeDataString($Query))&per_page=${MaximumResults}")
}

function Get-WinGetGitHubPullRequest {
  <#
  .SYNOPSIS
    Read authoritative PR state, author, base, head, and changed-file count.
  .PARAMETER PullRequestNumber
    Pull request number in the upstream repository.
  .PARAMETER RepoOwner
    Owner of the upstream repository.
  .PARAMETER RepoName
    Name of the upstream repository.
  #>
  param (
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$PullRequestNumber,
    [Parameter(Mandatory)][string]$RepoOwner,
    [Parameter(Mandatory)][string]$RepoName
  )
  Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/pulls/${PullRequestNumber}"
}

function Set-WinGetGitHubPullRequestTitle {
  <#
  .SYNOPSIS
    Update a PR title without replacing its body or review metadata.
  .PARAMETER PullRequestNumber
    Pull request number in the upstream repository.
  .PARAMETER Title
    New title for the submitted version.
  .PARAMETER RepoOwner
    Owner of the upstream repository.
  .PARAMETER RepoName
    Name of the upstream repository.
  .PARAMETER Token
    Optional string or SecureString credential for this title update only.
    When omitted, Invoke-GitHubApi uses the normal Dumplings token.
  #>
  param (
    [Parameter(Mandatory)][int]$PullRequestNumber,
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$RepoOwner,
    [Parameter(Mandatory)][string]$RepoName,
    [Parameter()][object]$Token
  )
  $TokenArguments = @{}
  if ($PSBoundParameters.ContainsKey('Token')) { $TokenArguments.Token = $Token }
  Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/pulls/${PullRequestNumber}" -Method Patch -Body @{ title = $Title } @TokenArguments
}

function Get-WinGetGitHubPullRequestFile {
  <#
  .SYNOPSIS
    Enumerate every changed file reported for a GitHub pull request.
  .DESCRIPTION
    Reads the paginated pull-request files endpoint in 100-item pages. GitHub
    limits this endpoint to 3,000 files; exceeding that limit is fatal because a
    partial list cannot be used for exact change comparison.
  .PARAMETER PullRequestNumber
    Number of the pull request to inspect.
  .PARAMETER RepoOwner
    Owner of the repository containing the pull request.
  .PARAMETER RepoName
    Name of the repository containing the pull request.
  .OUTPUTS
    Changed-file objects returned by GitHub.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The pull request number')]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$PullRequestNumber,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RepoName
  )

  $Files = [System.Collections.Generic.List[object]]::new()
  for ($Page = 1; $Page -le 30; $Page++) {
    # Invoke-RestMethod returns a JSON array as one pipeline
    # object. Wrapping that call in @() therefore creates a nested Object[] and
    # makes the complete page look like one file without filename/status
    # properties. Assignment preserves the JSON array itself, which foreach
    # can enumerate exactly once for both one-file and multi-file responses.
    $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/pulls/${PullRequestNumber}/files?per_page=100&page=${Page}"
    foreach ($File in $Response) { $Files.Add($File) }

    if ($Response.Count -lt 100) { return $Files.ToArray() }
  }

  throw "Pull request #${PullRequestNumber} contains at least 3,000 changed files; GitHub cannot return a complete file list for exact comparison."
}

function Close-WinGetGitHubPullRequest {
  <#
  .SYNOPSIS
    Close a pull request in a GitHub repository
  .PARAMETER PullRequestNumber
    The number of the pull request to close
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The number of the pull request to close')]
    [int]$PullRequestNumber,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName
  )

  return (Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/pulls/${PullRequestNumber}" -Method Patch -Body @{ state = 'closed' })
}

function Open-WinGetGitHubPullRequest {
  <#
  .SYNOPSIS
    Open a pull request in a GitHub repository
  .PARAMETER PullRequestNumber
    The number of the pull request to open
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The number of the pull request to open')]
    [int]$PullRequestNumber,
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName
  )

  return (Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/pulls/${PullRequestNumber}" -Method Patch -Body @{ state = 'open' })
}

function Get-WinGetGitHubApiTokenUser {
  <#
  .SYNOPSIS
    Read the account authenticated by a GitHub API token.
  .PARAMETER Token
    Optional string or SecureString credential to inspect without changing the
    normal Dumplings token. When omitted, use the default credential.
  .OUTPUTS
    GitHub user response containing the authenticated account's login.
  #>
  param ([Parameter()][object]$Token)

  $TokenArguments = @{}
  if ($PSBoundParameters.ContainsKey('Token')) { $TokenArguments.Token = $Token }
  return (Invoke-GitHubApi -Uri 'https://api.github.com/user' @TokenArguments)
}

function Get-WinGetGitHubIssueClosingKeyword {
  <#
  .SYNOPSIS
    Get the keyword a submission names a resolved issue with
  .DESCRIPTION
    GitHub accepts several spellings of each closing action and ignores the words around them, so a
    submission picks one documented form and uses it everywhere it names the issue.
  .PARAMETER Action
    The documented action whose keyword to use: close, fix, or resolve
  .OUTPUTS
    System.String. The keyword, for example 'Resolves'.
  #>
  [OutputType([string])]
  param (
    [Parameter(HelpMessage = 'The documented action whose keyword to use: close, fix, or resolve')]
    [ValidateSet('close', 'fix', 'resolve')]
    [string]$Action = 'resolve'
  )

  $Keyword = switch ($Action.ToLowerInvariant()) {
    'close' { 'closes' }
    'fix' { 'fixes' }
    'resolve' { 'resolves' }
  }
  if (-not ($DumplingsWinGetGitHubIssueClosingKeywords -contains $Keyword)) {
    throw "GitHub documents no '$Keyword' keyword that closes an issue. Use one of: $($DumplingsWinGetGitHubIssueClosingKeywords -join ', ')."
  }
  return [string]::Concat($Keyword.Substring(0, 1).ToUpperInvariant(), $Keyword.Substring(1))
}

function Select-WinGetGitHubIssueReference {
  <#
  .SYNOPSIS
    Find the issues a text names
  .DESCRIPTION
    GitHub autolinks an issue or pull request named by any of the forms its documentation lists, and
    writes each back the way the calling repository refers to it: '#number' for that repository itself
    and 'owner/repo#number' for any other. A bare number is not a reference, so ordinary text such as a
    version number never matches.
    https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/autolinked-references-and-urls#issues-and-pull-requests
  .PARAMETER Text
    The text to search, such as a pull request title or body
  .PARAMETER RepoOwner
    The owner of the repository the reference is written for; omit it to keep every repository name
  .PARAMETER RepoName
    The name of the repository the reference is written for; omit it to keep every repository name
  .OUTPUTS
    System.String[]. One normalized reference per issue, for example '#12' or 'octo-org/octo-repo#100'.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, Mandatory, ValueFromPipeline, HelpMessage = 'The text to search, such as a pull request title or body')]
    [AllowEmptyString()]
    [string]$Text,
    [Parameter(HelpMessage = 'The owner of the repository the reference is written for')]
    [string]$RepoOwner,
    [Parameter(HelpMessage = 'The name of the repository the reference is written for')]
    [string]$RepoName
  )

  # The documented forms are the '#number', 'GH-number', and 'owner/repo#number' shorthands, and the
  # issue or pull request URL, whose path carries the repository. The URL host is left open because a
  # GitHub Enterprise host serves the same paths under its own name.
  process {
    [regex]::Matches($Text, '(?:(?<Owner>[A-Za-z0-9_.-]+)/(?<Repo>[A-Za-z0-9_.-]+)#|GH-|https?://[^/\s]+/(?<UrlOwner>[A-Za-z0-9_.-]+)/(?<UrlRepo>[A-Za-z0-9_.-]+)/(?:issues|pull)/|#)(?<Number>\d+)(?!\d)', [Text.RegularExpressions.RegexOptions]::IgnoreCase) | ForEach-Object {
      $ReferenceOwner = $_.Groups['Owner'].Success ? $_.Groups['Owner'].Value : $_.Groups['UrlOwner'].Value
      $ReferenceRepo = $_.Groups['Repo'].Success ? $_.Groups['Repo'].Value : $_.Groups['UrlRepo'].Value
      $Number = $_.Groups['Number'].Value
      if ($ReferenceOwner -and $ReferenceRepo -and -not ($ReferenceOwner -ieq $RepoOwner -and $ReferenceRepo -ieq $RepoName)) {
        "${ReferenceOwner}/${ReferenceRepo}#${Number}"
      } else {
        "#${Number}"
      }
    }
  }
}

function New-WinGetGitHubIssueReference {
  <#
  .SYNOPSIS
    Name the issues a pull request resolves
  .DESCRIPTION
    GitHub reads the closing keyword only next to the issue, so each reference names exactly one issue.
    The input keeps the shape a task setting or a command line writes, where the references arrive as
    one string or as several values separated by commas, semicolons, or whitespace, and where each of
    them may be a number, a '#' number, an 'owner/repo#number', or the URL of the issue.
  .PARAMETER IssueNumber
    The issue references, separated by commas, semicolons, or whitespace. Empty entries are ignored.
  .PARAMETER RepoOwner
    The owner of the repository the pull request targets, so that a reference to that repository reads
    as a bare number
  .PARAMETER RepoName
    The name of the repository the pull request targets, so that a reference to that repository reads as
    a bare number
  .PARAMETER Action
    The documented action whose keyword to use: close, fix, or resolve
  .OUTPUTS
    System.String[]. One reference per issue, for example 'Resolves #12'.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, HelpMessage = 'The issue references, separated by commas, semicolons, or whitespace')]
    [AllowNull()]
    [AllowEmptyString()]
    [AllowEmptyCollection()]
    [string[]]$IssueNumber,
    [Parameter(HelpMessage = 'The owner of the repository the pull request targets')]
    [string]$RepoOwner,
    [Parameter(HelpMessage = 'The name of the repository the pull request targets')]
    [string]$RepoName,
    [Parameter(HelpMessage = 'The documented action whose keyword to use: close, fix, or resolve')]
    [ValidateSet('close', 'fix', 'resolve')]
    [string]$Action = 'resolve'
  )

  process {
    $Keyword = Get-WinGetGitHubIssueClosingKeyword -Action $Action
    $IssueNumber | ForEach-Object {
      [string]$_ -split '[,;\s]+' | ForEach-Object {
        $Entry = $_
        if ($Entry) {
          # A bare number is one of the forms, so it becomes a reference before it is read back.
          $Reference = @(Select-WinGetGitHubIssueReference -Text ($Entry -match '^#?\d+$' ? "#$($Entry.TrimStart('#'))" : $Entry) -RepoOwner $RepoOwner -RepoName $RepoName)
          if ($Reference.Count -ne 1) { throw "'${Entry}' is not a reference to one issue." }
          "${Keyword} $($Reference[0])"
        }
      }
    }
  }
}

function Get-WinGetGitHubIssueReferencePlace {
  <#
  .SYNOPSIS
    Get the pull request parts a submission must name its resolved issues in
  .DESCRIPTION
    GitHub closes an issue only when the merge writes its closing keyword into the commit on the base
    branch. That commit holds the pull request title and the candidate commit messages, and the body
    only when the repository appends it, so a repository whose merge drops the body needs the issues in
    the title as well. GitHub reports the merge settings only to a caller that can administer the
    repository, so a repository that hides them gets both places rather than an unproven promise.
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  .OUTPUTS
    System.String[]. 'Body', and 'Title' when the merge does not keep the body.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The owner of the repository')]
    [string]$RepoOwner,
    [Parameter(Mandatory, HelpMessage = 'The name of the repository')]
    [string]$RepoName
  )

  $Repository = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}"
  if (-not $Repository.PSObject.Properties['squash_merge_commit_title']) {
    return [string[]]@('Body', 'Title')
  }

  # A rebase keeps neither the title nor the body, only the candidate commit messages.
  return -not (
    ($Repository.allow_squash_merge -and $Repository.squash_merge_commit_message -ne 'PR_BODY') -or
    ($Repository.allow_merge_commit -and $Repository.merge_commit_message -ne 'PR_BODY') -or
    $Repository.allow_rebase_merge
  ) ? [string[]]@('Body') : [string[]]@('Body', 'Title')
}

Export-ModuleMember -Function '*' -Variable 'DumplingsWinGetGitHubRepoDefaultOwner', 'DumplingsWinGetGitHubRepoDefaultName', 'DumplingsWinGetGitHubRepoDefaultBranch', 'DumplingsWinGetGitHubRepoDefaultRootPath', 'DumplingsWinGetGitHubIssueClosingKeywords'
