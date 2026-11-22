. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

# The submission flow is an orchestration function, so its decisions are asserted through the calls
# it makes instead of through extracted helpers. Version selection is driven only as far as the
# first repository read of the reference manifests.
BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Index.ps1') -Force

  function New-SubmissionFlowTask {
    param ([string]$Version)

    $Task = [pscustomobject]@{
      Config       = @{ WinGetIdentifier = 'Contoso.Test'; WinGetOriginRepoOwner = 'TestBot' }
      CurrentState = [ordered]@{ Version = $Version; Installer = @(); Locale = @() }
      Messages     = [Collections.Generic.List[string]]::new()
    }
    $Task | Add-Member -MemberType ScriptMethod -Name Log -Value { param($Message, $Level) $this.Messages.Add("[$Level] $Message") }
    return $Task
  }
}

Describe 'Send-WinGetManifest reference version selection' -Tag Unit {
  BeforeEach {
    $Global:DumplingsPreference = @{}
    $Global:DumplingsOutput = $TestDrive
    Mock Get-WinGetLocalRepoPath -ModuleName WinGetSubmission { $null }
    Mock Get-WinGetGitHubBranch -ModuleName WinGetSubmission { @{ object = @{ sha = 'A' * 40 } } }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetSubmission { @{ login = 'TestBot' } }
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetSubmission { @{ items = @() } }
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { @() }
    Mock Read-WinGetGitHubManifests -ModuleName WinGetSubmission { throw 'manifest read reached' }
  }

  It 'keeps a version that is already present as its own reference' {
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { @('1.0', '1.2', '2.0') }

    { Send-WinGetManifest -Task (New-SubmissionFlowTask -Version '1.2') } | Should -Throw '*manifest read reached*'

    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetSubmission -Times 1 -Exactly -ParameterFilter { $PackageVersion -eq '1.2' }
  }

  It 'models a version that is not present after the newest existing version' {
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { @('1.0', '1.2') }

    { Send-WinGetManifest -Task (New-SubmissionFlowTask -Version '1.5') } | Should -Throw '*manifest read reached*'

    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetSubmission -Times 1 -Exactly -ParameterFilter { $PackageVersion -eq '1.2' }
  }

  It 'matches the version text instead of a numerically equal version' {
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { @('1.2', '1.2.0') }

    { Send-WinGetManifest -Task (New-SubmissionFlowTask -Version '1.2.0') } | Should -Throw '*manifest read reached*'

    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetSubmission -Times 1 -Exactly -ParameterFilter { $PackageVersion -eq '1.2.0' }
  }

  It 'reads the manifest from the revision that version discovery used' {
    Mock Get-WinGetGitHubPackageVersion -ModuleName WinGetSubmission { @('1.0', '1.2') }

    { Send-WinGetManifest -Task (New-SubmissionFlowTask -Version '1.2') } | Should -Throw '*manifest read reached*'

    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetSubmission -Times 1 -Exactly -ParameterFilter { $RepoBranch -eq ('A' * 40) }
  }

  It 'stops before reading manifests when the package has no versions yet' {
    { Send-WinGetManifest -Task (New-SubmissionFlowTask -Version '1.0') } | Should -Throw '*Could not find any version*'

    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetSubmission -Times 0 -Exactly
    Should -Invoke Get-WinGetGitHubBranch -ModuleName WinGetSubmission -Times 1 -Exactly
  }
}
