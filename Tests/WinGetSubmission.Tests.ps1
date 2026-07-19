# SPDX-License-Identifier: MIT

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
