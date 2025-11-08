# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

# The locale for sorting strings
$Culture = 'en-US'
# The scriptblock for sorting natural numbers
$ToNatural = { [regex]::Replace($_, '\d+', { $args[0].Value.PadLeft(20) }) }

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
    [string]$RootPath
  )

  process {
    $Prefix = Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -RootPath $RootPath

    # https://docs.github.com/rest/git/trees#get-a-tree
    $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/trees/${RepoBranch}:${Prefix}?recursive=true"
    $Response.tree |
      ForEach-Object -Process { if ($_.type -eq 'blob' -and $_.path -match "^([^/]+)/$([regex]::Escape($PackageIdentifier))\.yaml$") { $Matches[1] } } |
      Sort-Object -Property $Script:ToNatural -Stable -Culture $Script:Culture
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
    [string]$RepoRef
  )

  # Get the reference of the source branch
  $SourceBranch = Get-WinGetGitHubBranch -RepoOwner $RepoOwner -RepoName $RepoName -RepoBranch $RepoBranch

  # Create the new branch
  $Response = Invoke-GitHubApi -Uri "https://api.github.com/repos/${RepoOwner}/${RepoName}/git/refs" -Method Post -Body @{
    ref = $PSCmdlet.ParameterSetName -eq 'Ref' ? $RepoRef : "refs/heads/${Name}"
    sha = $SourceBranch.object.sha
  }

  return $Response
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
    [string]$CommitMessage
  )

  process {
    $Prefix = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : (Get-WinGetGitHubPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath)

    # The manifests to write
    $Manifests = [ordered]@{}

    # Add version manifest to write
    if (-not $Manifest.Version) { throw 'The version manifest is null or empty.' }
    $Manifests["${PackageIdentifier}.yaml"] = $Manifest.Version

    # Add installer manifest to write if it exists
    if ($Manifest.Installer) { $Manifests["${PackageIdentifier}.installer.yaml"] = $Manifest.Installer }

    # Add locale manifests to write if they exist
    $Manifest.Locale.GetEnumerator() | ForEach-Object -Process { $Manifests["${PackageIdentifier}.locale.$($_.Key).yaml"] = $_.Value }

    # Write manifests
    $Response = Invoke-GitHubApi -Uri 'https://api.github.com/graphql' -Method Post -Body @{
      query = @"
mutation {
  createCommitOnBranch(
    input: {
      branch: {
        repositoryNameWithOwner: "${RepoOwner}/${RepoName}"
        branchName: "${RepoBranch}"
      }
      message: {
        headline: "${CommitMessage}"
      }
      fileChanges: {
        additions: [
          $($Manifests.GetEnumerator() | ForEach-Object -Process {
            @"
          {
            path: "${Prefix}/$($_.Key)"
            contents: "$([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_.Value.ReplaceLineEndings("`n"))))"
          }
"@ } | Join-String -Separator ",`n")
        ]
      }
      expectedHeadOid: "${RepoSha}"
    }
  ) {
    commit {
      oid
    }
  }
}
"@
    }

    return $Response.data.createCommitOnBranch.commit.oid
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
    $PSBoundParameters.Remove('RepoSha'); $PSBoundParameters.Remove('CommitMessage')
    $Manifests = Get-WinGetGitHubManifests @PSBoundParameters

    $Response = Invoke-GitHubApi -Uri 'https://api.github.com/graphql' -Method Post -Body @{
      query = @"
mutation {
  createCommitOnBranch(
    input: {
      branch: {
        repositoryNameWithOwner: "${RepoOwner}/${RepoName}"
        branchName: "${RepoBranch}"
      }
      message: {
        headline: "${CommitMessage}"
      }
      fileChanges: {
        deletions: [
          $($Manifests | ForEach-Object -Process {
            @"
          {
            path: "${Prefix}/$($_.path)"
          }
"@ } | Join-String -Separator ",`n")
        ]
      }
      expectedHeadOid: "${RepoSha}"
    }
  ) {
    commit {
      oid
    }
  }
}
"@
    }

    return $Response.data.createCommitOnBranch.commit.oid
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
  .PARAMETER RepoOwner
    The owner of the repository
  .PARAMETER RepoName
    The name of the repository
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The search query for finding pull requests')]
    [string]$Query
  )

  return (Invoke-GitHubApi -Uri "https://api.github.com/search/issues?q=$([Uri]::EscapeDataString($Query))")
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
    Get the user information of the provided GitHub API token
  #>

  return (Invoke-GitHubApi -Uri 'https://api.github.com/user')
}

Export-ModuleMember -Function '*' -Variable 'DumplingsWinGetGitHubRepoDefaultOwner', 'DumplingsWinGetGitHubRepoDefaultName', 'DumplingsWinGetGitHubRepoDefaultBranch', 'DumplingsWinGetGitHubRepoDefaultRootPath'
