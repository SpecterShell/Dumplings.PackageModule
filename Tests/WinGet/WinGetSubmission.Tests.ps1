. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsModuleRoot 'Index.ps1')
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetGitHubRepo.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\WinGet\WinGetSubmission.psm1') -Force

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

Describe 'Get-WinGetPullRequestConflictInfo' -Tag Unit {
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

Describe 'Test-WinGetInstallerUrlIntersection' -Tag Unit {
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

Describe 'Invoke-WinGetSubmissionManifestRemoval' -Tag Unit {
  BeforeEach {
    $Script:RemovalLogs = [System.Collections.Generic.List[object]]::new()
    $Script:RemovalTask = [pscustomobject]@{}
    $Script:RemovalTask | Add-Member -MemberType ScriptMethod -Name Log -Value {
      param($Message, $Level)
      $Script:RemovalLogs.Add([pscustomobject]@{ Message = $Message; Level = $Level })
    }
    $Script:RemovalParameters = @{
      Task              = $Script:RemovalTask
      PackageIdentifier = 'Vendor.Package'
      PackageVersion    = '1.0'
      RepoOwner         = 'DumplingsBot'
      RepoName          = 'winget-pkgs'
      RepoBranch        = 'test-branch'
      RepoSha           = ('a' * 40)
      RootPath          = 'manifests'
      CommitMessage     = 'Remove version'
    }
  }

  It 'retains the new-version commit and warns when inferred removal fails' {
    Mock Remove-WinGetGitHubManifests -ModuleName WinGetSubmission { throw 'tree rejected the deletion' }

    $Result = Invoke-WinGetSubmissionManifestRemoval @Script:RemovalParameters -WarnOnFailure

    $Result.Succeeded | Should -BeFalse
    $Result.CommitSha | Should -Be ('a' * 40)
    $Result.ErrorMessage | Should -BeLike '*tree rejected the deletion*'
    $Script:RemovalLogs | Should -HaveCount 1
    $Script:RemovalLogs[0].Level | Should -BeExactly 'Warning'
    $Script:RemovalLogs[0].Message | Should -BeLike '*Continuing with the new-version commit only*'
  }

  It 'still throws when an explicitly configured removal fails' {
    Mock Remove-WinGetGitHubManifests -ModuleName WinGetSubmission { throw 'tree rejected the deletion' }

    { Invoke-WinGetSubmissionManifestRemoval @Script:RemovalParameters } | Should -Throw '*tree rejected the deletion*'
    $Script:RemovalLogs | Should -BeNullOrEmpty
  }

  It 'returns the removal commit when deletion succeeds' {
    Mock Remove-WinGetGitHubManifests -ModuleName WinGetSubmission { 'b' * 40 }

    $Result = Invoke-WinGetSubmissionManifestRemoval @Script:RemovalParameters -WarnOnFailure

    $Result.Succeeded | Should -BeTrue
    $Result.CommitSha | Should -Be ('b' * 40)
    $Result.ErrorMessage | Should -BeNullOrEmpty
    $Script:RemovalLogs | Should -BeNullOrEmpty
  }
}

Describe 'Test-WinGetGitHubFileChangeEquality' -Tag Unit {
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

  It 'rejects incomplete GitHub file evidence instead of declaring it identical' {
    $Reference = [pscustomobject]@{ filename = 'manifests/a.yaml'; sha = ('a' * 40) }
    $Difference = Get-TestFileChange -FileName 'manifests/a.yaml' -Status modified -Sha ('a' * 40)

    { Test-WinGetGitHubFileChangeEquality -ReferenceChange $Reference -DifferenceChange $Difference } |
      Should -Throw '*missing its filename or status*'
  }
}

Describe 'Get-WinGetSubmissionCandidateChange' -Tag Unit {
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

Describe 'Send-WinGetManifest comparison failure policy' -Tag Unit {
  BeforeAll {
    $Script:SavedPreference = Get-Variable -Name DumplingsPreference -Scope Global -ErrorAction Ignore
    $Script:SavedOutput = Get-Variable -Name DumplingsOutput -Scope Global -ErrorAction Ignore
  }

  BeforeEach {
    $Global:DumplingsPreference = @{ WinGetOriginRepoOwner = 'DumplingsBot' }
    $Global:DumplingsOutput = $TestDrive
    $Script:SubmissionTask = [pscustomobject]@{
      Config         = @{ WinGetPackageIdentifier = 'Vendor.Package'; RemoveLastVersion = $false }
      CurrentState   = [ordered]@{
        Version   = '2.0'
        Installer = @([ordered]@{ Architecture = 'x64'; InstallerUrl = 'https://example.test/setup-v2.exe' })
        Locale    = @()
      }
      InstallerFiles = [ordered]@{}
      Logs           = [Collections.Generic.List[object]]::new()
    }
    $Script:SubmissionTask | Add-Member -MemberType ScriptMethod -Name Log -Value {
      param($Message, $Level)
      $this.Logs.Add([pscustomobject]@{ Message = $Message; Level = $Level })
    }
    $Script:ExistingPullRequest = Get-TestPullRequest -Author DumplingsBot -Number 42
    $Script:ExistingPullRequest.title = 'New version: Vendor.Package version 2.0'
    $Script:CandidateChange = Get-TestFileChange -FileName 'manifests/v/Vendor/Package/2.0/Vendor.Package.yaml' -Status added -Sha ('c' * 40)

    # Isolate the submission orchestration from source reads, parsing, validation,
    # and GitHub writes. The real comparison helper still exercises its retries.
    Mock Get-WinGetLocalRepoPath -ModuleName WinGetSubmission { $null }
    Mock Get-WinGetGitHubBranch -ModuleName WinGetSubmission { @{ object = @{ sha = 'a' * 40 } } }
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { '1.0' }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetSubmission { @{ login = 'DumplingsBot' } }
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission { @{ items = @() } }
    Mock Read-WinGetGitHubManifests -ModuleName WinGetSubmission { 'reference manifests' }
    Mock ConvertFrom-WinGetManifestYaml -ModuleName WinGetSubmission { @{ Installers = @() } }
    Mock Update-WinGetManifest -ModuleName WinGetSubmission { @{ Installers = @() } }
    Mock ConvertTo-WinGetManifestYaml -ModuleName WinGetSubmission { @{ Version = 'candidate manifest'; Locale = @{} } }
    Mock Add-WinGetLocalManifests -ModuleName WinGetSubmission {}
    Mock Test-WinGetManifest -ModuleName WinGetSubmission {}
    Mock New-WinGetGitHubBranch -ModuleName WinGetSubmission { @{ object = @{ sha = 'a' * 40 } } }
    Mock Add-WinGetGitHubManifests -ModuleName WinGetSubmission { 'b' * 40 }
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission { @{ files = @($Script:CandidateChange) } }
    Mock Get-WinGetGitHubPullRequestFile -ModuleName WinGetSubmission { $Script:CandidateChange }
    Mock Invoke-WinGetSubmissionCandidateBranchCleanup -ModuleName WinGetSubmission {}
    Mock New-WinGetGitHubPullRequest -ModuleName WinGetSubmission {
      @{ number = 43; title = 'New version: Vendor.Package version 2.0'; html_url = 'https://example.test/pr/43' }
    }
    Mock Close-WinGetGitHubPullRequest -ModuleName WinGetSubmission {}
    Mock Start-Sleep -ModuleName WinGetSubmission {}
    Mock Get-WinGetPendingPackageReference -ModuleName WinGetSubmission { throw 'Pending fallback must not run without opt-in and a missing package.' }
    Mock Update-WinGetPendingPackagePullRequest -ModuleName WinGetSubmission {}
    Mock Test-WinGetPendingPackageContentEquality -ModuleName WinGetSubmission { $false }
  }

  It 'keeps the missing-package error when fallback is disabled' {
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*Could not find any version*'
    Should -Invoke Get-WinGetPendingPackageReference -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke New-WinGetGitHubBranch -ModuleName WinGetSubmission -Exactly 0
  }

  It 'rejects string-valued opt-in settings instead of treating quoted false as true' {
    $Script:SubmissionTask.Config.WinGetPendingPackageFallback = 'false'
    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*must be a YAML boolean*'
    Should -Invoke Get-WinGetPendingPackageReference -ModuleName WinGetSubmission -Exactly 0
  }

  It 'does not search PR templates for an existing package even when globally enabled' {
    $Global:DumplingsPreference.WinGetPendingPackageFallback = $true
    Send-WinGetManifest -Task $Script:SubmissionTask
    Should -Invoke Get-WinGetPendingPackageReference -ModuleName WinGetSubmission -Exactly 0
  }

  It 'lets a task disable a globally enabled fallback' {
    $Global:DumplingsPreference.WinGetPendingPackageFallback = $true
    $Script:SubmissionTask.Config.WinGetPendingPackageFallback = $false
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*Could not find any version*'
    Should -Invoke Get-WinGetPendingPackageReference -ModuleName WinGetSubmission -Exactly 0
  }

  It 'requires an explicit trusted-user list before fallback discovery' {
    $Script:SubmissionTask.Config.WinGetPendingPackageFallback = $true
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*requires WinGetPendingPackageTrustedUsers*'
  }

  It 'uses the selected PR model and defaults to updating that PR: <Action>' -ForEach @(
    @{ Action = 'UpdatePullRequest'; Dry = $false; Local = $false }
    @{ Action = 'NewPullRequest'; Dry = $false; Local = $false }
    @{ Action = 'UpdatePullRequest'; Dry = $true; Local = $false }
    @{ Action = 'UpdatePullRequest'; Dry = $false; Local = $true }
  ) {
    $Script:SubmissionTask.Config.WinGetPendingPackageFallback = $true
    $Script:SubmissionTask.Config.WinGetPendingPackageTrustedUsers = @('TrustedBot')
    if ($Action -eq 'NewPullRequest') { $Script:SubmissionTask.Config.WinGetPendingPackageAction = $Action }
    $Global:DumplingsPreference.Dry = $Dry
    $Script:PendingPullRequest = Get-TestPullRequest -Author TrustedBot -Number 40
    $Script:PendingPullRequest.title = 'New package: Vendor.Package version 2.0'
    $Script:PendingReference = [pscustomobject]@{
      PullRequest = $Script:PendingPullRequest; PackageVersion = '1.0'; HeadSha = 'd' * 40
      Manifest = @{ Installers = @(); PackageIdentifier = 'Vendor.Package' }
    }
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    Mock Get-WinGetPendingPackageReference -ModuleName WinGetSubmission { $Script:PendingReference }
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission { @{ items = @($Script:PendingPullRequest) } }
    Mock Remove-WinGetGitHubManifests -ModuleName WinGetSubmission { throw 'A pending template must not produce upstream deletions.' }
    $Script:SubmissionTask.Config.RemoveLastVersion = $true
    if ($Local) {
      Mock Get-WinGetLocalRepoPath -ModuleName WinGetSubmission { $TestDrive }
      Mock Get-WinGetLocalPackageVersion -ModuleName WinGetSubmission { throw 'The absent local package must not be read.' }
    }

    Send-WinGetManifest -Task $Script:SubmissionTask

    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke Test-WinGetManifest -ModuleName WinGetSubmission -Exactly 1
    Should -Invoke Get-WinGetPendingPackageReference -ModuleName WinGetSubmission -Exactly 1 -ParameterFilter { $TrustedUser.Count -eq 1 -and $TrustedUser[0] -eq 'TrustedBot' }
    $UpdateCount = (-not $Dry -and $Action -eq 'UpdatePullRequest') ? 1 : 0
    $NewCount = (-not $Dry -and $Action -eq 'NewPullRequest') ? 1 : 0
    Should -Invoke Update-WinGetPendingPackagePullRequest -ModuleName WinGetSubmission -Exactly $UpdateCount
    Should -Invoke New-WinGetGitHubBranch -ModuleName WinGetSubmission -Exactly $NewCount
    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly $NewCount
    Should -Invoke Close-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke Remove-WinGetGitHubManifests -ModuleName WinGetSubmission -Exactly 0
    if ($NewCount) {
      Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 1 -ParameterFilter { $Body -like '*Reference manifests:*pull/40*referenced PR remains open*' }
    }
  }

  It 'refuses downgrading a newer pending manifest' {
    $Script:SubmissionTask.Config.WinGetPendingPackageFallback = $true
    $Script:SubmissionTask.Config.WinGetPendingPackageTrustedUsers = @('TrustedBot')
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    Mock Get-WinGetPendingPackageReference -ModuleName WinGetSubmission { @{ PackageVersion = '3.0' } }
    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*Refusing to downgrade*'
    Should -Invoke Update-WinGetManifest -ModuleName WinGetSubmission -Exactly 0
  }

  It 'lets an explicit empty task allowlist disable inherited trust' {
    $Global:DumplingsPreference.WinGetPendingPackageFallback = $true
    $Global:DumplingsPreference.WinGetPendingPackageTrustedUsers = @('TrustedBot')
    $Script:SubmissionTask.Config.WinGetPendingPackageTrustedUsers = @()
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*requires WinGetPendingPackageTrustedUsers*'
    Should -Invoke Get-WinGetPendingPackageReference -ModuleName WinGetSubmission -Exactly 0
  }

  It 'handles matching manifests in <_> mode without creating another PR' -ForEach @('UpdatePullRequest', 'NewPullRequest') {
    $Script:SubmissionTask.Config.WinGetPendingPackageFallback = $true
    $Script:SubmissionTask.Config.WinGetPendingPackageTrustedUsers = @('TrustedBot')
    $Script:SubmissionTask.Config.WinGetPendingPackageAction = $_
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    Mock Get-WinGetPendingPackageReference -ModuleName WinGetSubmission {
      @{ PackageVersion = '2.0'; HeadSha = 'd' * 40; Manifest = @{ Installers = @() }; PullRequest = @{ number = 40; html_url = 'https://example.test/pr/40' } }
    }
    Mock Test-WinGetPendingPackageContentEquality -ModuleName WinGetSubmission { $true }
    Send-WinGetManifest -Task $Script:SubmissionTask
    $UpdateCount = ($_ -eq 'UpdatePullRequest') ? 1 : 0
    Should -Invoke Update-WinGetPendingPackagePullRequest -ModuleName WinGetSubmission -Exactly $UpdateCount -ParameterFilter { $Title -ceq 'New package: Vendor.Package version 2.0' }
    Should -Invoke New-WinGetGitHubBranch -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 0
  }

  It 'does not silently create a new PR when an in-place update fails' {
    $Script:SubmissionTask.Config.WinGetPendingPackageFallback = $true
    $Script:SubmissionTask.Config.WinGetPendingPackageTrustedUsers = @('TrustedBot')
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { $null }
    Mock Get-WinGetPendingPackageReference -ModuleName WinGetSubmission {
      @{ PackageVersion = '1.0'; HeadSha = 'd' * 40; Manifest = @{ Installers = @() }; PullRequest = @{ number = 40; html_url = 'https://example.test/pr/40' } }
    }
    Mock Update-WinGetPendingPackagePullRequest -ModuleName WinGetSubmission { throw 'No push permission' }
    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*No push permission*'
    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 0
  }

  It 'warns after exhausted comparison retries and still creates a pull request' {
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission { throw 'GitHub temporarily unavailable' }

    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Not -Throw

    Should -Invoke Get-WinGetGitHubComparison -ModuleName WinGetSubmission -Exactly 6
    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 1
    Should -Invoke Invoke-WinGetSubmissionCandidateBranchCleanup -ModuleName WinGetSubmission -Exactly 0
    $Warnings = @($Script:SubmissionTask.Logs.Where({ $_.Level -eq 'Warning' }))
    $Warnings | Should -HaveCount 1
    $Warnings[0].Message | Should -BeLike '*Failed to compare the candidate changes*GitHub temporarily unavailable*'
    $Warnings[0].Message | Should -BeLike '*continue without empty-change or exact duplicate pull-request checks*'
  }

  It 'skips exact duplicate checks when the candidate comparison failed and closes old PRs after replacement' {
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission { throw 'comparison failed' }
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission { @{ items = @($Script:ExistingPullRequest) } }

    Send-WinGetManifest -Task $Script:SubmissionTask

    Should -Invoke Get-WinGetGitHubPullRequestFile -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 1
    Should -Invoke Close-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 1 -ParameterFilter { $PullRequestNumber -eq 42 }
    Should -Invoke Invoke-WinGetSubmissionCandidateBranchCleanup -ModuleName WinGetSubmission -Exactly 0
  }

  It 'still removes a candidate branch when the comparison confirms no changes' {
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission { @{ files = @() } }

    Send-WinGetManifest -Task $Script:SubmissionTask

    Should -Invoke Get-WinGetGitHubComparison -ModuleName WinGetSubmission -Exactly 6
    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke Invoke-WinGetSubmissionCandidateBranchCleanup -ModuleName WinGetSubmission -Exactly 1
  }

  It 'still preserves an existing PR when both comparisons establish identical changes' {
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission { @{ items = @($Script:ExistingPullRequest) } }

    Send-WinGetManifest -Task $Script:SubmissionTask

    Should -Invoke Get-WinGetGitHubPullRequestFile -ModuleName WinGetSubmission -Exactly 1
    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke Close-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 0
    Should -Invoke Invoke-WinGetSubmissionCandidateBranchCleanup -ModuleName WinGetSubmission -Exactly 1
    $Script:SubmissionTask.Logs.Message | Should -Contain 'Existing pull request #42 contains exactly the same changes. Preserving it and aborting redundant submission: https://github.com/microsoft/winget-pkgs/pull/42'
  }

  It 'warns and submits when only the existing PR file comparison fails' {
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission { @{ items = @($Script:ExistingPullRequest) } }
    Mock Get-WinGetGitHubPullRequestFile -ModuleName WinGetSubmission { throw 'PR files temporarily unavailable' }

    Send-WinGetManifest -Task $Script:SubmissionTask

    Should -Invoke New-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 1
    Should -Invoke Close-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 1 -ParameterFilter { $PullRequestNumber -eq 42 }
    $Script:SubmissionTask.Logs.Where({ $_.Level -eq 'Warning' }).Message | Should -BeLike '*Normal replacement submission will continue*PR files temporarily unavailable*'
  }

  It 'still throws a PR creation failure and leaves existing PRs open' {
    Mock Get-WinGetGitHubComparison -ModuleName WinGetSubmission { throw 'comparison failed' }
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission { @{ items = @($Script:ExistingPullRequest) } }
    Mock New-WinGetGitHubPullRequest -ModuleName WinGetSubmission { throw 'PR creation failed' }

    { Send-WinGetManifest -Task $Script:SubmissionTask } | Should -Throw '*PR creation failed*'

    Should -Invoke Close-WinGetGitHubPullRequest -ModuleName WinGetSubmission -Exactly 0
  }

  AfterAll {
    if ($Script:SavedPreference) { $Global:DumplingsPreference = $Script:SavedPreference.Value }
    else { Remove-Variable -Name DumplingsPreference -Scope Global -ErrorAction Ignore }
    if ($Script:SavedOutput) { $Global:DumplingsOutput = $Script:SavedOutput.Value }
    else { Remove-Variable -Name DumplingsOutput -Scope Global -ErrorAction Ignore }
  }
}

Describe 'Select-WinGetPullRequestForClosure' -Tag Unit {
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
