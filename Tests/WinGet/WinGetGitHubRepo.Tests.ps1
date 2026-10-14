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
