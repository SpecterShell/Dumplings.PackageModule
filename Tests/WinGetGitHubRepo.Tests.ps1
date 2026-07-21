# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetGitHubRepo.psm1') -Force
}

Describe 'Add-WinGetGitHubManifests' {
  It 'throws when GitHub GraphQL reports an error instead of a commit' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ errors = @([pscustomobject]@{ message = 'Expected head OID does not match' }) }
    }

    { Add-WinGetGitHubManifests -PackageIdentifier 'Vendor.Package' -PackageVersion '1.0' -RepoOwner DumplingsBot -RepoName winget-pkgs -RepoBranch 'test-branch' -RepoSha ('a' * 40) -RootPath 'manifests' -Manifest ([ordered]@{ Version = 'version'; Installer = 'installer'; Locale = [ordered]@{} }) -CommitMessage 'Test' } |
      Should -Throw '*Expected head OID does not match*'
  }

  It 'returns the created commit OID' {
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      [pscustomobject]@{ data = [pscustomobject]@{ createCommitOnBranch = [pscustomobject]@{ commit = [pscustomobject]@{ oid = ('b' * 40) } } } }
    }

    $Result = Add-WinGetGitHubManifests -PackageIdentifier 'Vendor.Package' -PackageVersion '1.0' -RepoOwner DumplingsBot -RepoName winget-pkgs -RepoBranch 'test-branch' -RepoSha ('a' * 40) -RootPath 'manifests' -Manifest ([ordered]@{ Version = 'version'; Installer = 'installer'; Locale = [ordered]@{} }) -CommitMessage 'Test'

    $Result | Should -Be ('b' * 40)
  }
}

Describe 'Remove-WinGetGitHubManifests' {
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

Describe 'Get-WinGetGitHubComparison' {
  It 'uses owner-qualified and URI-escaped fork references' {
    $Script:GitHubApiArguments = $null
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Script:GitHubApiArguments = $args
      [pscustomobject]@{ status = 'ahead'; files = @([pscustomobject]@{ filename = 'manifest.yaml' }) }
    }

    $Result = Get-WinGetGitHubComparison `
      -Base 'microsoft:master' `
      -Head 'DumplingsBot:Package/1.0 branch' `
      -RepoOwner microsoft `
      -RepoName winget-pkgs

    $Result.status | Should -Be ahead
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly
    $UriIndex = $Script:GitHubApiArguments.IndexOf('-Uri')
    $Script:GitHubApiArguments[$UriIndex + 1] | Should -Be 'https://api.github.com/repos/microsoft/winget-pkgs/compare/microsoft%3Amaster...DumplingsBot%3APackage%2F1.0%20branch'
  }
}

Describe 'Get-WinGetGitHubPullRequestFile' {
  It 'reads all pages until GitHub returns fewer than 100 files' {
    $Script:GitHubApiUris = [System.Collections.Generic.List[string]]::new()
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $UriIndex = $args.IndexOf('-Uri')
      $RequestUri = [string]$args[$UriIndex + 1]
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

Describe 'Remove-WinGetGitHubBranch' {
  It 'deletes the escaped branch reference' {
    $Script:GitHubApiArguments = $null
    Mock Invoke-GitHubApi -ModuleName WinGetGitHubRepo {
      $Script:GitHubApiArguments = $args
      [pscustomobject]@{ deleted = $true }
    }

    $null = Remove-WinGetGitHubBranch -Name 'Package/1.0 branch' -RepoOwner DumplingsBot -RepoName winget-pkgs

    Should -Invoke Invoke-GitHubApi -ModuleName WinGetGitHubRepo -Times 1 -Exactly
    $UriIndex = $Script:GitHubApiArguments.IndexOf('-Uri')
    $MethodIndex = $Script:GitHubApiArguments.IndexOf('-Method')
    $Script:GitHubApiArguments[$UriIndex + 1] | Should -Be 'https://api.github.com/repos/DumplingsBot/winget-pkgs/git/refs/heads/Package%2F1.0%20branch'
    $Script:GitHubApiArguments[$MethodIndex + 1] | Should -Be Delete
  }
}
