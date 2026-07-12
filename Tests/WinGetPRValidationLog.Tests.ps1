# SPDX-License-Identifier: MIT

BeforeAll {
  $Script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
  $Script:ValidationLogScript = Join-Path $Script:RepositoryRoot '.agent\skills\author-winget-manifest\scripts\Get-WinGetPRValidationLog.ps1'

  function Get-TestAzureArtifactPage {
    param([int]$ArtifactId = 42)
    [pscustomobject]@{
      data = [pscustomobject]@{
        artifacts = @([pscustomobject]@{ name = 'InstallationVerificationLogs'; artifactId = $ArtifactId })
      }
    }
  }

  function Get-TestAzureContributionResponse {
    $Providers = [pscustomobject]@{}
    $Providers | Add-Member -NotePropertyName 'ms.vss-build-web.run-artifacts-download-data-provider' -NotePropertyValue ([pscustomobject]@{
        downloadUrl = 'https://example.invalid/InstallationVerificationLogs.zip'
      })
    [pscustomobject]@{ dataProviders = $Providers }
  }
}

Describe 'Get-WinGetPRValidationLog' {
  It 'downloads an Azure artifact from a direct pipeline URL' {
    Mock Invoke-RestMethod {
      if ([string]$Uri -match 'HierarchyQuery') { return Get-TestAzureContributionResponse }
      return Get-TestAzureArtifactPage
    }
    Mock Invoke-WebRequest {
      [IO.File]::WriteAllBytes([IO.Path]::GetFullPath($OutFile), [byte[]](1, 2, 3, 4))
    }
    $OutputDirectory = Join-Path $TestDrive 'PipelineUrl'

    $Result = & $Script:ValidationLogScript `
      -PipelineUrl 'https://dev.azure.com/shine-oss/winget-pkgs/_build/results?buildId=987654' `
      -ArtifactName InstallationVerificationLogs `
      -OutputDirectory $OutputDirectory `
      -NoExpand

    $Result.BuildId | Should -Be 987654
    $Result.ArtifactName | Should -Be 'InstallationVerificationLogs'
    $Result.Status | Should -Be 'Downloaded'
    Test-Path -LiteralPath $Result.ArchivePath | Should -BeTrue
    $Result.ExtractedPath | Should -BeNullOrEmpty
    Should -Invoke Invoke-WebRequest -Times 1 -Exactly
  }

  It 'resolves the latest wingetbot pipeline comment for a PR' {
    Mock Invoke-RestMethod {
      $RequestUri = [string]$Uri
      if ($RequestUri -match 'api\.github\.com/.+/comments') {
        return @(
          [pscustomobject]@{
            id = 100
            created_at = '2026-07-10T00:00:00Z'
            user = [pscustomobject]@{ login = 'wingetbot' }
            body = 'Validation Pipeline Run [older](https://dev.azure.com/shine-oss/winget-pkgs/_build/results?buildId=111)'
          },
          [pscustomobject]@{
            id = 101
            created_at = '2026-07-11T00:00:00Z'
            user = [pscustomobject]@{ login = 'wingetbot' }
            body = 'Validation Pipeline Run [newer](https://dev.azure.com/shine-oss/winget-pkgs/_build/results?buildId=222)'
          }
        )
      }
      if ($RequestUri -match 'HierarchyQuery') { return Get-TestAzureContributionResponse }
      return Get-TestAzureArtifactPage
    }
    Mock Invoke-WebRequest { throw 'WhatIf must not download artifacts.' }

    $Result = & $Script:ValidationLogScript `
      -PullRequest 123456 `
      -ArtifactName InstallationVerificationLogs `
      -OutputDirectory (Join-Path $TestDrive 'PullRequest') `
      -WhatIf

    $Result.PullRequest | Should -Be 123456
    $Result.BuildId | Should -Be 222
    $Result.Status | Should -Be 'WhatIf'
    Should -Invoke Invoke-WebRequest -Times 0 -Exactly
  }

  It 'contains no GitHub mutation endpoint calls' {
    $Text = Get-Content -LiteralPath $Script:ValidationLogScript -Raw
    $Text | Should -Not -Match 'set_issue_state|post_comment|/labels|/pulls/.+/merge'
    $Text | Should -Match 'InstallationVerificationLogs'
    $Text | Should -Match 'ValidationResult'
    $Text | Should -Match ([regex]::Escape('$env:GH_DUMPLINGS_TOKEN'))
    $Text | Should -Not -Match ([regex]::Escape('$env:GITHUB_TOKEN'))
  }
}
