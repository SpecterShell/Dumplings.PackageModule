. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Networking\GitHub.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetGitHubRepo.psm1') -Force
}

Describe 'Add-WinGetGitHubManifests' -Tag Unit {
  It 'creates a branch from captured revision evidence without fetching a moving source branch' {
    Mock Get-WinGetGitHubBranch -ModuleName WinGetGitHubRepo { throw 'Must not resolve the branch again' }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { [pscustomobject]@{ object = [pscustomobject]@{ sha = $Body.sha } } }
    $Revision = 'c' * 40
    $Result = New-WinGetGitHubBranch -Name 'new-branch' -RepoOwner 'Example' -RepoName 'repo' -RepoBranch main -SourceSha $Revision
    $Result.object.sha | Should -Be $Revision
    Should -Invoke Get-WinGetGitHubBranch -ModuleName WinGetGitHubRepo -Times 0 -Exactly
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Body.sha -eq $Revision -and $Body.ref -eq 'refs/heads/new-branch' }
  }
  It 'throws when GitHub GraphQL reports an error instead of a commit' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ errors = @([pscustomobject]@{ message = 'Expected head OID does not match' }) }
    }

    { Add-WinGetGitHubManifests -PackageIdentifier 'Vendor.Package' -PackageVersion '1.0' -RepoOwner DumplingsBot -RepoName winget-pkgs -RepoBranch 'test-branch' -RepoSha ('a' * 40) -RootPath 'manifests' -Manifest ([ordered]@{ Version = 'version'; Installer = 'installer'; Locale = [ordered]@{} }) -CommitMessage 'Test' } |
      Should -Throw '*Expected head OID does not match*'
  }

  It 'returns the created commit OID' {
    $Script:GraphQLMaximumRetryCount = $null
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Script:GraphQLMaximumRetryCount = $MaximumRetryCount
      [pscustomobject]@{ data = [pscustomobject]@{ createCommitOnBranch = [pscustomobject]@{ commit = [pscustomobject]@{ oid = ('b' * 40) } } } }
    }

    $Result = Add-WinGetGitHubManifests -PackageIdentifier 'Vendor.Package' -PackageVersion '1.0' -RepoOwner DumplingsBot -RepoName winget-pkgs -RepoBranch 'test-branch' -RepoSha ('a' * 40) -RootPath 'manifests' -Manifest ([ordered]@{ Version = 'version'; Installer = 'installer'; Locale = [ordered]@{} }) -CommitMessage 'Test'

    $Result | Should -Be ('b' * 40)
    $Script:GraphQLMaximumRetryCount | Should -Be 0
  }

  It 'combines replacement manifests and pending-version deletions in one guarded commit' {
    Mock Invoke-WinGetGitHubCommitMutation -ModuleName WinGetGitHubRepo { 'b' * 40 }
    $Content = [ordered]@{ Version = "version`r`n"; Installer = 'installer'; Locale = [ordered]@{} }
    $null = Add-WinGetGitHubManifests -PackageIdentifier Vendor.Package -PackageVersion '2.0' -RepoOwner Bot -RepoName winget-pkgs -RepoBranch pending -RepoSha ('a' * 40) -RootPath manifests -Manifest $Content -RemovePath 'manifests/v/Vendor/Package/1.0/Vendor.Package.yaml' -RequireUnchangedHead -CommitMessage Test
    Should -Invoke Invoke-WinGetGitHubCommitMutation -ModuleName WinGetGitHubRepo -Exactly 1 -ParameterFilter {
      $RequireUnchangedHead -and $FileChanges.additions.Count -eq 2 -and $FileChanges.deletions.Count -eq 1 -and $FileChanges.deletions[0].path -eq 'manifests/v/Vendor/Package/1.0/Vendor.Package.yaml'
    }
  }

  It 'rejects deletion outside the package or overlapping additions: <Path>' -ForEach @(
    @{ Path = 'README.md' }
    @{ Path = 'manifests/v/Vendor/Package/../Other.yaml' }
    @{ Path = 'manifests/v/Vendor/Package/2.0/Vendor.Package.yaml' }
  ) {
    Mock Invoke-WinGetGitHubCommitMutation -ModuleName WinGetGitHubRepo { throw 'Must not mutate' }
    { Add-WinGetGitHubManifests -PackageIdentifier Vendor.Package -PackageVersion '2.0' -RepoOwner Bot -RepoName winget-pkgs -RepoBranch pending -RepoSha ('a' * 40) -RootPath manifests -Manifest ([ordered]@{ Version = 'version'; Locale = @{} }) -RemovePath $Path -CommitMessage Test } | Should -Throw
    Should -Invoke Invoke-WinGetGitHubCommitMutation -ModuleName WinGetGitHubRepo -Exactly 0
  }
}

Describe 'Missing GitHub package detection' -Tag Unit {
  It 'returns no versions for confirmed 404 only when explicitly permitted' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { throw [InvalidOperationException]::new('GitHub 404', [Net.Http.HttpRequestException]::new('missing', $null, [Net.HttpStatusCode]::NotFound)) }
    @(Get-WinGetGitHubPackageVersion -PackageIdentifier Vendor.Package -RepoOwner Bot -RepoName winget-pkgs -RepoBranch ('a' * 40) -RootPath manifests -AllowMissing) | Should -BeNullOrEmpty
    { Get-WinGetGitHubPackageVersion -PackageIdentifier Vendor.Package -RepoOwner Bot -RepoName winget-pkgs -RepoBranch ('a' * 40) -RootPath manifests } | Should -Throw '*404*'
  }

  It 'does not hide non-missing HTTP failures: <Status>' -ForEach @(@{ Status = 401 }, @{ Status = 403 }, @{ Status = 429 }, @{ Status = 500 }) {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { throw [Net.Http.HttpRequestException]::new('API failed', $null, [Net.HttpStatusCode]$Status) }
    { Get-WinGetGitHubPackageVersion -PackageIdentifier Vendor.Package -RepoOwner Bot -RepoName winget-pkgs -RepoBranch ('a' * 40) -RootPath manifests -AllowMissing } | Should -Throw '*API failed*'
  }
}

Describe 'Invoke-WinGetGitHubCommitMutation' -Tag Unit {
  BeforeEach {
    $Script:OldHead = 'a' * 40
    $Script:NewHead = 'b' * 40
    $Script:FinalHead = 'c' * 40
    $Script:ObservedExpectedHeads = [System.Collections.Generic.List[string]]::new()
    Mock Start-Sleep -ModuleName WinGetGitHubRepo
  }

  It 'recovers a commit that succeeded before its response was lost' {
    Mock Get-WinGetGitHubBranch -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ object = [pscustomobject]@{ sha = $Script:NewHead } }
    }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      if ($Uri.AbsolutePath -eq '/graphql') {
        $Script:ObservedExpectedHeads.Add([string]$Body.variables.input.expectedHeadOid)
        throw 'The connection closed before a response was received'
      }
      [pscustomobject]@{
        message = 'Test commit'
        parents = @([pscustomobject]@{ sha = $Script:OldHead })
      }
    }

    $Result = Invoke-WinGetGitHubCommitMutation `
      -RepoOwner DumplingsBot `
      -RepoName winget-pkgs `
      -RepoBranch test-branch `
      -ExpectedHeadOid $Script:OldHead `
      -CommitMessage 'Test commit' `
      -FileChanges ([ordered]@{ additions = @([ordered]@{ path = 'manifest.yaml'; contents = 'YQ==' }) }) `
      -Operation 'the test commit'

    $Result | Should -BeExactly $Script:NewHead
    $Script:ObservedExpectedHeads | Should -Be @($Script:OldHead)
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Uri.AbsolutePath -eq '/graphql' -and $MaximumRetryCount -eq 0 }
  }

  It 'retries against the observed head when another commit advanced the branch' {
    $Script:GraphQLAttempt = 0
    Mock Get-WinGetGitHubBranch -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ object = [pscustomobject]@{ sha = $Script:NewHead } }
    }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      if ($Uri.AbsolutePath -eq '/graphql') {
        $Script:GraphQLAttempt++
        $Script:ObservedExpectedHeads.Add([string]$Body.variables.input.expectedHeadOid)
        if ($Script:GraphQLAttempt -eq 1) { throw 'Expected branch head did not match' }
        return [pscustomobject]@{ data = [pscustomobject]@{ createCommitOnBranch = [pscustomobject]@{ commit = [pscustomobject]@{ oid = $Script:FinalHead } } } }
      }
      [pscustomobject]@{
        message = 'Another commit'
        parents = @([pscustomobject]@{ sha = ('f' * 40) })
      }
    }

    $Result = Invoke-WinGetGitHubCommitMutation `
      -RepoOwner DumplingsBot `
      -RepoName winget-pkgs `
      -RepoBranch test-branch `
      -ExpectedHeadOid $Script:OldHead `
      -CommitMessage 'Test commit' `
      -FileChanges ([ordered]@{ deletions = @([ordered]@{ path = 'manifest.yaml' }) }) `
      -Operation 'the test commit'

    $Result | Should -BeExactly $Script:FinalHead
    $Script:ObservedExpectedHeads | Should -Be @($Script:OldHead, $Script:NewHead)
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 2 -Exactly -ParameterFilter { $Uri.AbsolutePath -eq '/graphql' -and $MaximumRetryCount -eq 0 }
  }

  It 'refuses to replay a pending-PR mutation over an unrelated commit' {
    Mock Get-WinGetGitHubBranch -ModuleName WinGetGitHubRepo { @{ object = @{ sha = $Script:NewHead } } }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      if ($Uri.AbsolutePath -eq '/graphql') { throw 'Expected head mismatch' }
      @{ message = 'Human review fix'; parents = @(@{ sha = $Script:OldHead }) }
    }
    { Invoke-WinGetGitHubCommitMutation -RepoOwner Bot -RepoName winget-pkgs -RepoBranch pending -ExpectedHeadOid $Script:OldHead -CommitMessage Test -FileChanges @{ additions = @() } -Operation Test -RequireUnchangedHead } | Should -Throw '*Refusing to overwrite concurrent changes*'
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Exactly 1 -ParameterFilter { $Uri.AbsolutePath -eq '/graphql' }
  }
}

Describe 'Remove-WinGetGitHubManifests' -Tag Unit {
  It 'returns only the created commit OID' {
    Mock Get-WinGetGitHubManifests -ModuleName WinGetGitHubRepo { @([pscustomobject]@{ path = 'Vendor.Package.yaml' }) }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ data = [pscustomobject]@{ createCommitOnBranch = [pscustomobject]@{ commit = [pscustomobject]@{ oid = ('c' * 40) } } } }
    }

    $Result = @(Remove-WinGetGitHubManifests -PackageIdentifier 'Vendor.Package' -PackageVersion '1.0' -RepoOwner DumplingsBot -RepoName winget-pkgs -RepoBranch 'test-branch' -RepoSha ('a' * 40) -RootPath 'manifests' -CommitMessage 'Remove version')

    $Result.Count | Should -Be 1
    $Result[0] | Should -Be ('c' * 40)
  }
}

Describe 'Get-WinGetGitHubComparison' -Tag Unit {
  It 'uses owner-qualified and URI-escaped fork references' {
    $Script:GitHubApiUri = $null
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Script:GitHubApiUri = $Uri.AbsoluteUri
      [pscustomobject]@{ status = 'ahead'; files = @([pscustomobject]@{ filename = 'manifest.yaml' }) }
    }

    $Result = Get-WinGetGitHubComparison `
      -Base 'microsoft:master' `
      -Head 'DumplingsBot:Package/1.0 branch' `
      -RepoOwner microsoft `
      -RepoName winget-pkgs

    $Result.status | Should -Be ahead
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly
    $Script:GitHubApiUri | Should -Be 'https://api.github.com/repos/microsoft/winget-pkgs/compare/microsoft%3Amaster...DumplingsBot%3APackage%2F1.0%20branch'
  }
}

Describe 'Set-WinGetGitHubPullRequestTitle' -Tag Unit {
  It 'patches only the title on the selected upstream PR' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {}
    $null = Set-WinGetGitHubPullRequestTitle -PullRequestNumber 42 -Title 'New package: Vendor.Package version 2.0' -RepoOwner microsoft -RepoName winget-pkgs
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Exactly 1 -ParameterFilter {
      $Uri.AbsoluteUri -ceq 'https://api.github.com/repos/microsoft/winget-pkgs/pulls/42' -and $Method -eq 'Patch' -and $Body.Count -eq 1 -and $Body.title -ceq 'New package: Vendor.Package version 2.0'
    }
  }

  It 'forwards an explicit credential only to the title request' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {}
    $null = Set-WinGetGitHubPullRequestTitle -PullRequestNumber 42 -Title 'New package: Vendor.Package version 2.0' -RepoOwner microsoft -RepoName winget-pkgs -Token 'test-author-token'
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Exactly 1 -ParameterFilter {
      $Token -ceq 'test-author-token' -and $Method -eq 'Patch' -and $Body.Count -eq 1 -and $Body.title -ceq 'New package: Vendor.Package version 2.0'
    }
  }
}

Describe 'Get-WinGetGitHubApiTokenUser' -Tag Unit {
  It 'uses the default credential when no token is supplied' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { @{ login = 'DefaultBot' } }
    (Get-WinGetGitHubApiTokenUser).login | Should -BeExactly 'DefaultBot'
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Exactly 1 -ParameterFilter { $Uri.AbsoluteUri -ceq 'https://api.github.com/user' -and $null -eq $Token }
  }

  It 'reads the account authenticated by an explicit credential' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { @{ login = 'TrustedAuthor' } }
    (Get-WinGetGitHubApiTokenUser -Token 'test-author-token').login | Should -BeExactly 'TrustedAuthor'
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Exactly 1 -ParameterFilter { $Uri.AbsoluteUri -ceq 'https://api.github.com/user' -and $Token -ceq 'test-author-token' }
  }
}

Describe 'Get-WinGetGitHubPullRequestFile' -Tag Unit {
  It 'enumerates a JSON array returned as one Invoke-RestMethod pipeline object' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Page = [object[]]@(
        [pscustomobject]@{ filename = 'manifest-1.yaml'; status = 'modified'; sha = ('a' * 40) }
        [pscustomobject]@{ filename = 'manifest-2.yaml'; status = 'added'; sha = ('b' * 40) }
      )
      Write-Output -NoEnumerate $Page
    }

    $Files = @(Get-WinGetGitHubPullRequestFile -PullRequestNumber 42 -RepoOwner microsoft -RepoName winget-pkgs)

    $Files.Count | Should -Be 2
    $Files.filename | Should -Be @('manifest-1.yaml', 'manifest-2.yaml')
    $Files.status | Should -Be @('modified', 'added')
  }

  It 'reads all pages until GitHub returns fewer than 100 files' {
    $Script:GitHubApiUris = [System.Collections.Generic.List[string]]::new()
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $RequestUri = [string]$Uri
      $Script:GitHubApiUris.Add($RequestUri)
      if ($RequestUri -match 'page=1$') {
        return 1..100 | ForEach-Object { [pscustomobject]@{ filename = "file-${_}" } }
      }
      return [pscustomobject]@{ filename = 'file-101' }
    }

    $Files = @(Get-WinGetGitHubPullRequestFile -PullRequestNumber 42 -RepoOwner microsoft -RepoName winget-pkgs)

    $Files.Count | Should -Be 101
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 2 -Exactly
    $Script:GitHubApiUris | Should -Be @(
      'https://api.github.com/repos/microsoft/winget-pkgs/pulls/42/files?per_page=100&page=1'
      'https://api.github.com/repos/microsoft/winget-pkgs/pulls/42/files?per_page=100&page=2'
    )
  }
}

Describe 'Remove-WinGetGitHubBranch' -Tag Unit {
  It 'deletes the escaped branch reference' {
    $Script:GitHubApiParameters = $null
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Script:GitHubApiParameters = [ordered]@{ Uri = $Uri.AbsoluteUri; Method = $Method }
      [pscustomobject]@{ deleted = $true }
    }

    $null = Remove-WinGetGitHubBranch -Name 'Package/1.0 branch' -RepoOwner DumplingsBot -RepoName winget-pkgs

    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly
    $Script:GitHubApiParameters.Uri | Should -Be 'https://api.github.com/repos/DumplingsBot/winget-pkgs/git/refs/heads/Package%2F1.0%20branch'
    $Script:GitHubApiParameters.Method | Should -Be Delete
  }
}

Describe 'Get-WinGetGitHubPackageAncestorPath' -Tag Unit {
  It 'returns the containing folders from the closest parent up to the first-character folder' {
    $Result = @(Get-WinGetGitHubPackageAncestorPath -PackageIdentifier 'SpecterShell.Dumplings' -RootPath 'manifests')

    $Result.Count | Should -Be 2
    $Result[0] | Should -Be 'manifests/s/SpecterShell'
    $Result[1] | Should -Be 'manifests/s'
  }

  It 'returns every sub-publisher folder of a nested publisher' {
    $Result = @(Get-WinGetGitHubPackageAncestorPath -PackageIdentifier 'Vendor.Studio.Product' -RootPath 'manifests')

    ($Result -join '|') | Should -Be 'manifests/v/Vendor/Studio|manifests/v/Vendor|manifests/v'
  }

  It 'omits the root path when no root path is supplied' {
    $Result = @(Get-WinGetGitHubPackageAncestorPath -PackageIdentifier 'SpecterShell.Dumplings')

    ($Result -join '|') | Should -Be 's/SpecterShell|s'
  }
}

Describe 'Get-WinGetGitHubCommitPage' -Tag Unit {
  It 'reports a single page when GitHub returns no Link header' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('a' * 40) } }

    $Result = Get-WinGetGitHubCommitPage -Uri 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs&per_page=1&page=1'

    @($Result.Commits).Count | Should -Be 1
    $Result.Commits[0].sha | Should -Be ('a' * 40)
    $Result.LastPage | Should -Be 1
  }

  It 'reports an empty page when the path has no commit' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { }

    $Result = Get-WinGetGitHubCommitPage -Uri 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs&per_page=1&page=1'

    @($Result.Commits).Count | Should -Be 0
    $Result.LastPage | Should -Be 1
  }

  It 'asks for the response headers that carry the page count' {
    $Script:RequestedHeaders = $null
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Script:RequestedHeaders = $ResponseHeadersVariable
      [pscustomobject]@{ sha = ('a' * 40) }
    }
    Mock Get-GitHubApiResponseHeader -ModuleName WinGetGitHubRepo { }

    $null = Get-WinGetGitHubCommitPage -Uri 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs&per_page=1&page=1'

    $Script:RequestedHeaders | Should -Not -BeNullOrEmpty
  }

  It 'reports the last page advertised by the Link header' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('a' * 40) } }
    Mock Get-GitHubApiResponseHeader -ModuleName WinGetGitHubRepo {
      '<https://api.github.com/repositories/1/commits?path=manifests%2Fs&per_page=1&page=2>; rel="next", <https://api.github.com/repositories/1/commits?path=manifests%2Fs&per_page=1&page=57>; rel="last"'
    }

    $Result = Get-WinGetGitHubCommitPage -Uri 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs&per_page=1&page=1'

    $Result.LastPage | Should -Be 57
  }

  It 'reports a further page without a last page when GitHub omits it' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('a' * 40) } }
    Mock Get-GitHubApiResponseHeader -ModuleName WinGetGitHubRepo {
      '<https://api.github.com/repositories/1/commits?path=manifests%2Fs&per_page=1&page=2>; rel="next"'
    }

    $Result = Get-WinGetGitHubCommitPage -Uri 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs&per_page=1&page=1'

    $Result.HasMorePages | Should -BeTrue
    $Result.LastPage | Should -Be 1
  }

  It 'reports no further page for a single page response' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('a' * 40) } }
    Mock Get-GitHubApiResponseHeader -ModuleName WinGetGitHubRepo { }

    $Result = Get-WinGetGitHubCommitPage -Uri 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs&per_page=1&page=1'

    $Result.HasMorePages | Should -BeFalse
  }
}

Describe 'Get-WinGetGitHubHistoryAnchor' -Tag Unit {
  It 'reads the newest commit of the escaped branch at or before the requested date' {
    $Script:AnchorUris = [System.Collections.Generic.List[string]]::new()
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Script:AnchorUris.Add($Uri)
      [pscustomobject]@{ sha = ('e' * 40) }
    }

    $Result = Get-WinGetGitHubHistoryAnchor -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'feature/new-version' -Until ([datetime]'2021-11-16T19:32:32Z')

    $Result.sha | Should -Be ('e' * 40)
    $Script:AnchorUris.Count | Should -Be 1
    $Script:AnchorUris[0] | Should -Be 'https://api.github.com/repos/microsoft/winget-pkgs/commits?sha=feature%2Fnew-version&per_page=1&until=2021-11-16T19:32:32Z'
  }

  It 'returns nothing when the branch has no commit that early' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { }

    $Result = @(Get-WinGetGitHubHistoryAnchor -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master' -Until ([datetime]'2016-01-01T00:00:00Z'))

    $Result.Count | Should -Be 0
  }
}

Describe 'Get-WinGetGitHubOldestPathCommitPage' -Tag Unit {
  BeforeAll {
    $Script:NewestHistoryCommit = [pscustomobject]@{
      sha    = ('d' * 40)
      commit = [pscustomobject]@{ committer = [pscustomobject]@{ date = '2026-11-16T19:32:32Z' } }
    }
  }

  It 'reads only the last page of a history that GitHub paginates' {
    $Script:CommitPageUris = [System.Collections.Generic.List[string]]::new()
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      $Script:CommitPageUris.Add($Uri)
      if ($Uri -match 'page=1$') {
        [pscustomobject]@{ Commits = @($Script:NewestHistoryCommit); LastPage = 42; HasMorePages = $false }
      } else {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('b' * 40) }); LastPage = 42; HasMorePages = $true }
      }
    }

    $Result = Get-WinGetGitHubOldestPathCommitPage -Path 'manifests/s/SpecterShell' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.Commits[-1].sha | Should -Be ('b' * 40)
    $Script:CommitPageUris.Count | Should -Be 2
    $Script:CommitPageUris[0] | Should -Be 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs%2FSpecterShell&per_page=100&sha=master&page=1'
    $Script:CommitPageUris[1] | Should -Be 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs%2FSpecterShell&per_page=100&sha=master&page=42'
  }

  It 'reads the only page of a history that fits one page' {
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('c' * 40) }); LastPage = 1; HasMorePages = $false }
    }
    Mock Get-WinGetGitHubHistoryAnchor -ModuleName WinGetGitHubRepo { throw 'a single page must not be narrowed' }

    $Result = Get-WinGetGitHubOldestPathCommitPage -Path 'manifests/s/SpecterShell' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.Commits[-1].sha | Should -Be ('c' * 40)
    Should -Invoke Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo -Times 1 -Exactly
  }

  It 'narrows a history that GitHub does not paginate with a commit anchor' {
    $Script:AnchorDates = [System.Collections.Generic.List[datetime]]::new()
    Mock Get-WinGetGitHubHistoryAnchor -ModuleName WinGetGitHubRepo {
      $Script:AnchorDates.Add($Until)
      [pscustomobject]@{ sha = ('f' * 40) }
    }
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      if ($Uri -match "sha=$('f' * 40)&page=1$") {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('9' * 40) }); LastPage = 12; HasMorePages = $false }
      } elseif ($Uri -match "sha=$('f' * 40)&page=12$") {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('8' * 40) }); LastPage = 12; HasMorePages = $false }
      } else {
        [pscustomobject]@{ Commits = @($Script:NewestHistoryCommit); LastPage = 1; HasMorePages = $true }
      }
    }

    $Result = Get-WinGetGitHubOldestPathCommitPage -Path 'manifests/s' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.Commits[-1].sha | Should -Be ('8' * 40)
    $Script:AnchorDates.Count | Should -Be 1
    $Script:AnchorDates[0] | Should -BeLessThan ([datetime]'2026-11-16T19:32:32Z')
    $Script:AnchorDates[0] | Should -BeGreaterThan ([datetime]'2016-11-16T19:32:32Z')
  }

  It 'moves the lower bound forward when the path does not exist at the anchor' {
    $Script:AnchorCount = 0
    Mock Get-WinGetGitHubHistoryAnchor -ModuleName WinGetGitHubRepo {
      $Script:AnchorCount++
      if ($Script:AnchorCount -eq 1) { [pscustomobject]@{ sha = ('1' * 40) } } else { [pscustomobject]@{ sha = ('2' * 40) } }
    }
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      if ($Uri -match "sha=$('1' * 40)") {
        [pscustomobject]@{ Commits = @(); LastPage = 1; HasMorePages = $false }
      } elseif ($Uri -match "sha=$('2' * 40)&page=1$") {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('7' * 40) }); LastPage = 3; HasMorePages = $false }
      } elseif ($Uri -match "sha=$('2' * 40)&page=3$") {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('6' * 40) }); LastPage = 3; HasMorePages = $false }
      } else {
        [pscustomobject]@{ Commits = @($Script:NewestHistoryCommit); LastPage = 1; HasMorePages = $true }
      }
    }

    $Result = Get-WinGetGitHubOldestPathCommitPage -Path 'manifests/s' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.Commits[-1].sha | Should -Be ('6' * 40)
    $Script:AnchorCount | Should -Be 2
  }

  It 'narrows repeatedly until the anchored listing fits one page' {
    $Script:AnchorDates = [System.Collections.Generic.List[datetime]]::new()
    Mock Get-WinGetGitHubHistoryAnchor -ModuleName WinGetGitHubRepo {
      $Script:AnchorDates.Add($Until)
      if ($Script:AnchorDates.Count -eq 1) { [pscustomobject]@{ sha = ('f' * 40) } } else { [pscustomobject]@{ sha = ('e' * 40) } }
    }
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      if ($Uri -match "sha=$('f' * 40)&page=1$") {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('4' * 40) }); LastPage = 1; HasMorePages = $true }
      } elseif ($Uri -match "sha=$('e' * 40)&page=1$") {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('3' * 40) }); LastPage = 2; HasMorePages = $false }
      } elseif ($Uri -match "sha=$('e' * 40)&page=2$") {
        [pscustomobject]@{ Commits = @([pscustomobject]@{ sha = ('2' * 40) }, [pscustomobject]@{ sha = ('5' * 40) }); LastPage = 2; HasMorePages = $false }
      } else {
        [pscustomobject]@{ Commits = @($Script:NewestHistoryCommit); LastPage = 1; HasMorePages = $true }
      }
    }

    $Result = Get-WinGetGitHubOldestPathCommitPage -Path 'manifests/s' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.Commits[-1].sha | Should -Be ('5' * 40)
    $Script:AnchorDates.Count | Should -Be 2
    $Script:AnchorDates[1] | Should -BeLessThan $Script:AnchorDates[0]
  }
  It 'reuses the newest page when the history cannot be narrowed' {
    Mock Get-WinGetGitHubHistoryAnchor -ModuleName WinGetGitHubRepo { }
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ Commits = @($Script:NewestHistoryCommit); LastPage = 1; HasMorePages = $true }
    }

    $Result = Get-WinGetGitHubOldestPathCommitPage -Path 'manifests/s' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.Commits[-1].sha | Should -Be ('d' * 40)
    Should -Invoke Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo -Times 1 -Exactly
  }
}

Describe 'Get-WinGetGitHubPathCommit' -Tag Unit {
  It 'reads the newest commit of the escaped path with a single request' {
    $Script:CommitPageUris = [System.Collections.Generic.List[string]]::new()
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      $Script:CommitPageUris.Add($Uri)
      [pscustomobject]@{
        Commits  = @([pscustomobject]@{ sha = ('a' * 40) }, [pscustomobject]@{ sha = ('b' * 40) })
        LastPage = 1
      }
    }

    $Result = Get-WinGetGitHubPathCommit -Path 'manifests/s/SpecterShell/Dumplings' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'feature/new-version'

    $Result.sha | Should -Be ('a' * 40)
    $Script:CommitPageUris.Count | Should -Be 1
    $Script:CommitPageUris[0] | Should -Be 'https://api.github.com/repos/microsoft/winget-pkgs/commits?path=manifests%2Fs%2FSpecterShell%2FDumplings&sha=feature%2Fnew-version&per_page=1'
  }

  It 'returns the last entry of the page that holds the oldest commit' {
    Mock Get-WinGetGitHubOldestPathCommitPage -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{
        Commits      = @([pscustomobject]@{ sha = ('b' * 40) }, [pscustomobject]@{ sha = ('c' * 40) })
        LastPage     = 42
        HasMorePages = $true
      }
    }

    $Result = Get-WinGetGitHubPathCommit -Path 'manifests/s' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master' -Oldest

    $Result.sha | Should -Be ('c' * 40)
    Should -Invoke Get-WinGetGitHubOldestPathCommitPage -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Path -eq 'manifests/s' -and $RepoBranch -eq 'master' }
  }

  It 'returns nothing when the path has no commit in that history' {
    Mock Get-WinGetGitHubCommitPage -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ Commits = @(); LastPage = 1; HasMorePages = $false }
    }

    $Result = @(Get-WinGetGitHubPathCommit -Path 'manifests/s/SpecterShell/Dumplings' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master')

    $Result.Count | Should -Be 0
  }
}
Describe 'Get-WinGetGitHubSubmissionCommit' -Tag Unit {
  It 'bases a published version on the newest commit of its version directory' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo {
      if ($Path -eq 'manifests/s/SpecterShell/Dumplings/1.2.3') { [pscustomobject]@{ sha = ('a' * 40) } }
    }

    $Result = Get-WinGetGitHubSubmissionCommit -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.2.3' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master' -RootPath 'manifests'

    $Result.sha | Should -Be ('a' * 40)
    $Result.Path | Should -Be 'manifests/s/SpecterShell/Dumplings/1.2.3'
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 1 -Exactly
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Path -eq 'manifests/s/SpecterShell/Dumplings/1.2.3' -and -not $Oldest }
  }

  It 'bases a new version on the newest commit of the package directory' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo {
      if ($Path -eq 'manifests/s/SpecterShell/Dumplings') { [pscustomobject]@{ sha = ('b' * 40) } }
    }

    $Result = Get-WinGetGitHubSubmissionCommit -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.2.3' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master' -RootPath 'manifests'

    $Result.sha | Should -Be ('b' * 40)
    $Result.Path | Should -Be 'manifests/s/SpecterShell/Dumplings'
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Path -eq 'manifests/s/SpecterShell/Dumplings/1.2.3' }
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Path -eq 'manifests/s/SpecterShell/Dumplings' -and -not $Oldest }
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 2 -Exactly
  }

  It 'bases a new package on the commit that established the closest containing folder' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo {
      if ($Path -eq 'manifests/s/SpecterShell') { [pscustomobject]@{ sha = ('c' * 40) } }
    }

    $Result = Get-WinGetGitHubSubmissionCommit -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.2.3' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master' -RootPath 'manifests'

    $Result.sha | Should -Be ('c' * 40)
    $Result.Path | Should -Be 'manifests/s/SpecterShell'
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Path -eq 'manifests/s/SpecterShell' -and $Oldest }
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 3 -Exactly
  }

  It 'walks up to the first-character folder when no closer folder has history' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo {
      if ($Path -eq 'manifests/s') { [pscustomobject]@{ sha = ('d' * 40) } }
    }

    $Result = Get-WinGetGitHubSubmissionCommit -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.2.3' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master' -RootPath 'manifests'

    $Result.sha | Should -Be ('d' * 40)
    $Result.Path | Should -Be 'manifests/s'
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Path -eq 'manifests/s/SpecterShell' -and $Oldest }
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 2 -Exactly -ParameterFilter { $Oldest }
  }

  It 'returns nothing when neither the version, the package nor a containing folder has history' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo { }

    $Result = @(Get-WinGetGitHubSubmissionCommit -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.2.3' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master' -RootPath 'manifests')

    $Result.Count | Should -Be 0
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 4 -Exactly
  }
}
Describe 'Get-WinGetGitHubManifestVersionCommit' -Tag Unit {
  It 'returns the newest tool commit that declares the manifest version' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('b' * 40) } }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Text = "`$ManifestVersion = '1.28.0'`r`nif (`$Settings.EnableOverride) { `$ManifestVersion = `$Settings.OverrideManifestVersion }`r`nif (`$ManifestVersion -ne 'latest') { }"
      [pscustomobject]@{ content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text)) }
    }

    $Result = Get-WinGetGitHubManifestVersionCommit -ManifestVersion '1.28.0' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.sha | Should -Be ('b' * 40)
    Should -Invoke Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter { $Path -eq 'Tools/YamlCreate.ps1' -and -not $Oldest -and $RepoBranch -eq 'master' }
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly -ParameterFilter {
      $Uri.AbsoluteUri -ceq "https://api.github.com/repos/microsoft/winget-pkgs/contents/Tools/YamlCreate.ps1?ref=$('b' * 40)"
    }
  }

  It 'accepts a tool that declares a newer version than the requested one' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('c' * 40) } }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("`$ManifestVersion = '1.28.0'")) }
    }

    $Result = Get-WinGetGitHubManifestVersionCommit -ManifestVersion '1.12.0' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master'

    $Result.sha | Should -Be ('c' * 40)
  }

  It 'returns nothing when the tool declares an older version' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('a' * 40) } }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("`$ManifestVersion = '1.24.0'")) }
    }

    $Result = @(Get-WinGetGitHubManifestVersionCommit -ManifestVersion '1.28.0' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master')

    $Result.Count | Should -Be 0
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly
  }

  It 'returns nothing when the tool has no recognizable version declaration' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo { [pscustomobject]@{ sha = ('a' * 40) } }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Write-Host "No version here"')) }
    }

    $Result = @(Get-WinGetGitHubManifestVersionCommit -ManifestVersion '1.28.0' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master')

    $Result.Count | Should -Be 0
  }

  It 'returns nothing without reading the tool when it has no commit history' {
    Mock Get-WinGetGitHubPathCommit -ModuleName WinGetGitHubRepo { $null }
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo { throw 'Must not read the tool without a commit' }

    $Result = @(Get-WinGetGitHubManifestVersionCommit -ManifestVersion '1.28.0' -RepoOwner microsoft -RepoName winget-pkgs -RepoBranch 'master')

    $Result.Count | Should -Be 0
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 0 -Exactly
  }
}

Describe 'GitHub issue reference forms' -Tag Unit {
  # Every form the documentation lists for an issue or pull request, with the reference the module reads from
  # text and writes into the pull request. A reference to the targeted repository reads back as a bare number.
  It 'reads and names the <Form> form' -ForEach @(
    @{ Form = "'#' number"; Written = '#12'; Reference = '#12' }
    @{ Form = "'GH-' number"; Written = 'GH-9'; Reference = '#9' }
    @{ Form = "'owner/repo#' number"; Written = 'octo-org/octo-repo#100'; Reference = 'octo-org/octo-repo#100' }
    @{ Form = "'owner/repo#' number of the targeted repository"; Written = 'example/REPO#13'; Reference = '#13' }
    @{ Form = 'issue URL'; Written = 'https://github.com/octo-org/octo-repo/issues/7'; Reference = 'octo-org/octo-repo#7' }
    @{ Form = 'pull request URL'; Written = 'https://github.com/octo-org/octo-repo/pull/7'; Reference = 'octo-org/octo-repo#7' }
    @{ Form = 'issue URL of the targeted repository'; Written = 'https://github.com/Example/repo/issues/18'; Reference = '#18' }
  ) {
    (Select-WinGetGitHubIssueReference -Text "Closes $Written" -RepoOwner Example -RepoName repo) | Should -Be $Reference
    (New-WinGetGitHubIssueReference -IssueNumber $Written -RepoOwner Example -RepoName repo) | Should -BeLike "* $Reference"
  }
}

Describe 'Select-WinGetGitHubIssueReference' -Tag Unit {
  It 'reads every reference a text names' {
    $Text = 'Closes #12, follows GH-9, resolves octo-org/octo-repo#100 and fixes https://github.com/octo-org/octo-repo/issues/7'

    @(Select-WinGetGitHubIssueReference -Text $Text -RepoOwner Example -RepoName repo).Count | Should -Be 4
  }

  It 'ignores numbers that name no issue' {
    @(Select-WinGetGitHubIssueReference -Text 'Vendor.Package version 2.0 ships 10 installers').Count | Should -Be 0
  }
}

Describe 'New-WinGetGitHubIssueReference' -Tag Unit {
  It 'names every issue of a free-form list with one documented keyword' {
    $References = @(New-WinGetGitHubIssueReference -IssueNumber '12, 13;14  ')

    $References.Count | Should -Be 3
    $Keywords = @($References | ForEach-Object -Process { ($_ -split ' ')[0] } | Select-Object -Unique)
    $Keywords.Count | Should -Be 1
    # The submission may only use a spelling GitHub documents, so the module states them.
    $DumplingsWinGetGitHubIssueClosingKeywords | Should -Contain $Keywords[0].ToLowerInvariant()
    $References[-1] | Should -BeLike "*#14"
  }

  It 'ignores empty entries and accepts a leading hash' {
    $References = @(New-WinGetGitHubIssueReference -IssueNumber @('#7', '', '  ', $null))

    $References.Count | Should -Be 1
    $References[0] | Should -BeLike '*#7'
  }

  It 'names a bare number entry' {
    (New-WinGetGitHubIssueReference -IssueNumber '15' -RepoOwner Example -RepoName repo) | Should -BeLike '* #15'
  }

  It 'rejects a value that is not a reference to an issue' {
    { New-WinGetGitHubIssueReference -IssueNumber 'the tracking issue' } | Should -Throw '*is not a reference to one issue*'
  }
}

Describe 'Get-WinGetGitHubIssueReferencePlace' -Tag Unit {
  It 'needs only the body when every merge method keeps the body' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{
        allow_squash_merge           = $true
        squash_merge_commit_title    = 'PR_TITLE'
        squash_merge_commit_message  = 'PR_BODY'
        allow_merge_commit           = $true
        merge_commit_title           = 'MERGE_MESSAGE'
        merge_commit_message         = 'PR_BODY'
        allow_rebase_merge           = $false
      }
    }

    (Get-WinGetGitHubIssueReferencePlace -RepoOwner Example -RepoName repo) -join ',' | Should -Be 'Body'
  }

  It 'needs the title when a squash merge drops the body' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{
        allow_squash_merge           = $true
        squash_merge_commit_title    = 'PR_TITLE'
        squash_merge_commit_message  = 'BLANK'
        allow_merge_commit           = $false
        allow_rebase_merge           = $false
      }
    }

    (Get-WinGetGitHubIssueReferencePlace -RepoOwner Example -RepoName repo) -join ',' | Should -Be 'Body,Title'
  }

  It 'needs the title when a rebase merge keeps only the commit messages' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{
        allow_squash_merge           = $false
        allow_merge_commit           = $false
        allow_rebase_merge           = $true
      }
    }

    (Get-WinGetGitHubIssueReferencePlace -RepoOwner Example -RepoName repo) -join ',' | Should -Be 'Body,Title'
  }

  It 'needs the title when the repository keeps its merge settings private' {
    # GitHub reports the merge settings only to a caller that can administer the repository.
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ full_name = 'Example/repo'; merges_url = 'https://api.github.com/repos/Example/repo/merges' }
    }

    (Get-WinGetGitHubIssueReferencePlace -RepoOwner Example -RepoName repo) -join ',' | Should -Be 'Body,Title'
  }
}
