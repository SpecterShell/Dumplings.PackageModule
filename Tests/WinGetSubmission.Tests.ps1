# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetSubmission.psm1') -Force

  function Get-TestPullRequest {
    param (
      [Parameter(Mandatory)][string]$Author,
      [Parameter(Mandatory)][int]$Number
    )

    [pscustomobject]@{
      number   = $Number
      title    = "Test package PR ${Number}"
      html_url = "https://github.com/microsoft/winget-pkgs/pull/${Number}"
      user     = [pscustomobject]@{ login = $Author }
    }
  }

  function Get-TestFileChange {
    param (
      [Parameter(Mandatory)][string]$FileName,
      [Parameter(Mandatory)][string]$Status,
      [string]$Sha,
      [string]$PreviousFileName
    )

    [pscustomobject]@{
      filename          = $FileName
      status            = $Status
      sha               = $Sha
      previous_filename = $PreviousFileName
    }
  }
}

Describe 'Get-WinGetPullRequestConflictInfo' {
  It 'excludes the token owner and blocks every other author by default' {
    $PullRequests = @(
      Get-TestPullRequest -Author 'DumplingsBot' -Number 1
      Get-TestPullRequest -Author 'ContributorA' -Number 2
      Get-TestPullRequest -Author 'ContributorB' -Number 3
    )

    $Info = Get-WinGetPullRequestConflictInfo -PullRequest $PullRequests -TokenUsername 'dumplingsbot'

    $Info.SelfPullRequests.number | Should -Be @(1)
    $Info.BlockingPullRequests.number | Should -Be @(2, 3)
    $Info.IgnoredPullRequests | Should -BeNullOrEmpty
    $Info.UsesConfiguredUserList | Should -BeFalse
  }

  It 'blocks only configured users and compares GitHub logins case-insensitively' {
    $PullRequests = @(
      Get-TestPullRequest -Author 'DumplingsBot' -Number 1
      Get-TestPullRequest -Author 'TrustedMaintainer' -Number 2
      Get-TestPullRequest -Author 'ContributorB' -Number 3
    )

    $Info = Get-WinGetPullRequestConflictInfo -PullRequest $PullRequests -TokenUsername 'DumplingsBot' -BlockingUsername @('trustedmaintainer') -UseConfiguredBlockingUsers

    $Info.SelfPullRequests.number | Should -Be @(1)
    $Info.BlockingPullRequests.number | Should -Be @(2)
    $Info.IgnoredPullRequests.number | Should -Be @(3)
    $Info.ConfiguredBlockingUsers | Should -Be @('trustedmaintainer')
  }

  It 'never treats the token owner as blocking even when configured' {
    $PullRequest = Get-TestPullRequest -Author 'DumplingsBot' -Number 1

    $Info = Get-WinGetPullRequestConflictInfo -PullRequest $PullRequest -TokenUsername 'dumplingsbot' -BlockingUsername @('DumplingsBot') -UseConfiguredBlockingUsers

    $Info.SelfPullRequests.number | Should -Be @(1)
    $Info.BlockingPullRequests | Should -BeNullOrEmpty
  }

  It 'allows every foreign author when an empty blocking list is explicitly configured' {
    $PullRequests = @(
      Get-TestPullRequest -Author 'ContributorA' -Number 2
      Get-TestPullRequest -Author 'ContributorB' -Number 3
    )

    $Info = Get-WinGetPullRequestConflictInfo -PullRequest $PullRequests -TokenUsername 'DumplingsBot' -BlockingUsername @() -UseConfiguredBlockingUsers

    $Info.BlockingPullRequests | Should -BeNullOrEmpty
    $Info.IgnoredPullRequests.number | Should -Be @(2, 3)
  }
}

Describe 'Test-WinGetInstallerUrlIntersection' {
  It 'does not report an unchanged URL when every ordered-dictionary URL changed' {
    $OldInstallers = @(
      [ordered]@{ Architecture = 'x86'; InstallerUrl = 'https://old.example/setup-x86.exe' }
      [ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://old.example/setup-x64.exe' }
    )
    $NewInstallers = @(
      [ordered]@{ Architecture = 'x86'; InstallerUrl = 'https://new.example/setup-x86.exe' }
      [ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://new.example/setup-x64.exe' }
    )

    Test-WinGetInstallerUrlIntersection -ReferenceInstaller $OldInstallers -DifferenceInstaller $NewInstallers | Should -BeFalse
  }

  It 'reports an unchanged URL when one ordered-dictionary URL is retained' {
    $OldInstallers = @(
      [ordered]@{ Architecture = 'x86'; InstallerUrl = 'https://example.test/setup-x86.exe' }
      [ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup-x64.exe' }
    )
    $NewInstallers = @(
      [ordered]@{ Architecture = 'x86'; InstallerUrl = 'https://example.test/setup-x86-v2.exe' }
      [ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup-x64.exe' }
    )

    Test-WinGetInstallerUrlIntersection -ReferenceInstaller $OldInstallers -DifferenceInstaller $NewInstallers | Should -BeTrue
  }

  It 'supports object-backed installer entries and ignores absent URLs' {
    $OldInstallers = @(
      [pscustomobject]@{ InstallerUrl = 'https://example.test/setup.exe' }
      [pscustomobject]@{ Architecture = 'x64' }
    )
    $NewInstallers = @(
      [pscustomobject]@{ InstallerUrl = 'https://example.test/setup.exe' }
      [pscustomobject]@{ InstallerUrl = '' }
    )

    Test-WinGetInstallerUrlIntersection -ReferenceInstaller $OldInstallers -DifferenceInstaller $NewInstallers | Should -BeTrue
  }

  It 'uses an ordinal comparison for path and query text' {
    $OldInstallers = @([ordered]@{ InstallerUrl = 'https://example.test/Setup.exe?Channel=Stable' })
    $NewInstallers = @([ordered]@{ InstallerUrl = 'https://example.test/setup.exe?channel=stable' })

    Test-WinGetInstallerUrlIntersection -ReferenceInstaller $OldInstallers -DifferenceInstaller $NewInstallers | Should -BeFalse
  }
}

Describe 'Test-WinGetGitHubFileChangeEquality' {
  It 'matches the same exact changes regardless of API result order' {
    $Reference = @(
      Get-TestFileChange -FileName 'manifests/a.yaml' -Status added -Sha ('a' * 40)
      Get-TestFileChange -FileName 'manifests/b.yaml' -Status modified -Sha ('b' * 40)
    )
    $Difference = @($Reference[1], $Reference[0])

    Test-WinGetGitHubFileChangeEquality -ReferenceChange $Reference -DifferenceChange $Difference | Should -BeTrue
  }

  It 'rejects a changed resulting blob at the same path' {
    $Reference = Get-TestFileChange -FileName 'manifests/a.yaml' -Status modified -Sha ('a' * 40)
    $Difference = Get-TestFileChange -FileName 'manifests/a.yaml' -Status modified -Sha ('b' * 40)

    Test-WinGetGitHubFileChangeEquality -ReferenceChange $Reference -DifferenceChange $Difference | Should -BeFalse
  }

  It 'treats removal of the same path as identical without relying on the old blob SHA' {
    $Reference = Get-TestFileChange -FileName 'manifests/old.yaml' -Status removed -Sha ('a' * 40)
    $Difference = Get-TestFileChange -FileName 'manifests/old.yaml' -Status removed -Sha ('b' * 40)

    Test-WinGetGitHubFileChangeEquality -ReferenceChange $Reference -DifferenceChange $Difference | Should -BeTrue
  }

  It 'includes the previous path when comparing renames' {
    $Reference = Get-TestFileChange -FileName 'manifests/new.yaml' -Status renamed -Sha ('a' * 40) -PreviousFileName 'manifests/old.yaml'
    $Difference = Get-TestFileChange -FileName 'manifests/new.yaml' -Status renamed -Sha ('a' * 40) -PreviousFileName 'manifests/other.yaml'

    Test-WinGetGitHubFileChangeEquality -ReferenceChange $Reference -DifferenceChange $Difference | Should -BeFalse
  }
}

Describe 'Get-WinGetSubmissionCandidateChange' {
  It 'returns the comparison files once the compare endpoint catches up' {
    $Script:CompareAttempts = 0
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission {
      $Script:CompareAttempts++
      if ($Script:CompareAttempts -lt 3) { return [pscustomobject]@{ files = @() } }
      return [pscustomobject]@{ files = @([pscustomobject]@{ filename = 'manifests/p.yaml' }) }
    }

    $Changes = @(Get-WinGetSubmissionCandidateChange -Base 'microsoft:master' -Head ('a' * 40) -RepoOwner microsoft -RepoName winget-pkgs -MaxRetryDelaySeconds 0)

    $Changes.Count | Should -Be 1
    $Script:CompareAttempts | Should -Be 3
  }

  It 'accepts an empty comparison only after the final attempt' {
    $Script:CompareAttempts = 0
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission {
      $Script:CompareAttempts++
      [pscustomobject]@{ files = @() }
    }

    $Changes = @(Get-WinGetSubmissionCandidateChange -Base 'microsoft:master' -Head ('a' * 40) -RepoOwner microsoft -RepoName winget-pkgs -MaxAttempts 3 -MaxRetryDelaySeconds 0)

    $Changes | Should -BeNullOrEmpty
    $Script:CompareAttempts | Should -Be 3
  }

  It 'throws the last compare error after repeated failures' {
    $Script:CompareAttempts = 0
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission {
      $Script:CompareAttempts++
      throw 'boom'
    }

    { Get-WinGetSubmissionCandidateChange -Base 'microsoft:master' -Head ('a' * 40) -RepoOwner microsoft -RepoName winget-pkgs -MaxAttempts 3 -MaxRetryDelaySeconds 0 } |
      Should -Throw '*boom*'
    $Script:CompareAttempts | Should -Be 3
  }
}

Describe 'Select-WinGetPullRequestForClosure' {
  It 'excludes already handled pull requests and removes duplicate API results' {
    $PullRequests = @(
      Get-TestPullRequest -Author DumplingsBot -Number 10
      Get-TestPullRequest -Author DumplingsBot -Number 11
      Get-TestPullRequest -Author DumplingsBot -Number 10
      Get-TestPullRequest -Author DumplingsBot -Number 12
    )

    $Selected = @(Select-WinGetPullRequestForClosure -PullRequest $PullRequests -ExcludedNumber 10, 12)

    $Selected.number | Should -Be @(11)
  }
}
