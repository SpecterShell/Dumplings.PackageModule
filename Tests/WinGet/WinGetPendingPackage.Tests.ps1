# SPDX-License-Identifier: Apache-2.0
. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  . (Join-Path $PSScriptRoot '..\..\Index.ps1')

  function New-TestPendingContent {
    param ([string]$Version = '1.0', [string]$Identifier = 'Vendor.Package')
    $Common = "PackageIdentifier: ${Identifier}`nPackageVersion: '${Version}'`n"
    $Header = "# Created with YamlCreate.ps1 Dumplings Mod`n# yaml-language-server: `$schema=https://aka.ms/winget-manifest."
    return [ordered]@{
      Version   = "${Header}version.1.12.0.schema.json`n${Common}DefaultLocale: en-US`nManifestType: version`nManifestVersion: 1.12.0`n"
      Installer = "${Header}installer.1.12.0.schema.json`n${Common}InstallerType: nullsoft`nInstallers:`n- Architecture: x64`n  InstallerUrl: https://example.test/setup.exe`n  InstallerSha256: $('A' * 64)`nManifestType: installer`nManifestVersion: 1.12.0`n"
      Locale    = [ordered]@{ 'en-US' = "${Header}defaultLocale.1.12.0.schema.json`n${Common}PackageLocale: en-US`nPublisher: Vendor`nPackageName: Package`nLicense: MIT`nShortDescription: Test package.`nManifestType: defaultLocale`nManifestVersion: 1.12.0`n" }
    }
  }

  function New-TestPendingPullRequest {
    param ([int]$Number = 42, [string]$Version = '1.0', [string]$Author = 'TrustedBot')
    [pscustomobject]@{
      number = $Number; state = 'open'; draft = $false; merged = $false
      title = "New package: Vendor.Package version ${Version}"
      html_url = "https://github.com/microsoft/winget-pkgs/pull/${Number}"
      updated_at = '2026-10-15T00:00:00Z'; changed_files = 3
      user = [pscustomobject]@{ login = $Author }
      base = [pscustomobject]@{ ref = 'master'; repo = [pscustomobject]@{ full_name = 'microsoft/winget-pkgs' } }
      head = [pscustomobject]@{
        sha = $Number.ToString('x40'); ref = 'pending-package'
        repo = [pscustomobject]@{ full_name = "${Author}/winget-pkgs"; default_branch = 'master' }
      }
    }
  }

  function New-TestPendingFiles {
    param ([string]$Version = '1.0')
    foreach ($Name in @('Vendor.Package.yaml', 'Vendor.Package.installer.yaml', 'Vendor.Package.locale.en-US.yaml')) {
      [pscustomobject]@{ filename = "manifests/v/Vendor/Package/${Version}/${Name}"; status = 'added' }
    }
  }

  function New-TestPendingTask {
    $Task = [pscustomobject]@{ Logs = [Collections.Generic.List[object]]::new() }
    $Task | Add-Member ScriptMethod Log { param($Message, $Level) $this.Logs.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
    return $Task
  }
}

Describe 'Trusted pending-package reference selection' -Tag Unit {
  BeforeEach {
    $Script:Task = New-TestPendingTask
    $Script:PullRequests = @{ 42 = New-TestPendingPullRequest }
    $Script:Versions = @{ 42 = '1.0' }
    $Script:Files = @{ 42 = @(New-TestPendingFiles) }
    $Script:Parameters = @{ Task = $Script:Task; PackageIdentifier = 'Vendor.Package'; TrustedUser = @('TrustedBot'); RepoOwner = 'microsoft'; RepoName = 'winget-pkgs'; RepoBranch = 'master'; RootPath = 'manifests' }
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage {
      @{ items = @($Script:PullRequests.Values); incomplete_results = $false; total_count = $Script:PullRequests.Count }
    }
    Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { $Script:PullRequests[[int]$PullRequestNumber] }
    Mock Get-WinGetGitHubPullRequestFile -ModuleName WinGetPendingPackage { $Script:Files[[int]$PullRequestNumber] }
    Mock Read-WinGetGitHubManifests -ModuleName WinGetPendingPackage {
      $Number = $Script:PullRequests.Keys.Where({ $Script:PullRequests[$_].head.sha -ceq $RepoBranch })[0]
      New-TestPendingContent -Version $Script:Versions[$Number]
    }
  }

  It 'selects a valid addition and reads content at its immutable head SHA' {
    try { $Result = Get-WinGetPendingPackageReference @Script:Parameters }
    catch { throw "$_ Candidate diagnostics: $($Script:Task.Logs.Message -join '; ')" }
    $Result.PackageVersion | Should -Be '1.0'
    $Result.Manifest.PackageIdentifier | Should -BeExactly 'Vendor.Package'
    $Result.Paths | Should -HaveCount 3
    Should -Invoke Find-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $Query -like '*is:open*' }
    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $RepoBranch -ceq (42).ToString('x40') -and $RepoOwner -eq 'TrustedBot' }
  }

  It 'ignores higher versions in closed or merged PRs' {
    foreach ($Number in 43, 44) {
      $Script:PullRequests[$Number] = New-TestPendingPullRequest -Number $Number -Version '10.0'
      $Script:Versions[$Number] = '10.0'
      $Script:Files[$Number] = @(New-TestPendingFiles -Version '10.0')
    }
    $Script:PullRequests[43].state = 'closed'
    $Script:PullRequests[44].merged = $true
    (Get-WinGetPendingPackageReference @Script:Parameters).PullRequest.number | Should -Be 42
    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 1
  }

  It 'chooses the highest manifest version rather than title or update time' {
    $Script:PullRequests[43] = New-TestPendingPullRequest -Number 43 -Version '10.0'
    $Script:PullRequests[42].title = 'New package: Vendor.Package version 999.0'
    $Script:PullRequests[42].updated_at = '2026-10-15T01:00:00Z'
    $Script:Versions[42] = '9.0'; $Script:Files[42] = @(New-TestPendingFiles -Version '9.0')
    $Script:Versions[43] = '10.0'
    $Script:Files[43] = @(New-TestPendingFiles -Version '10.0')
    (Get-WinGetPendingPackageReference @Script:Parameters).PullRequest.number | Should -Be 43
  }

  It 'uses recent update time and then PR number to break equal-version ties' {
    $Script:PullRequests[43] = New-TestPendingPullRequest -Number 43
    $Script:Versions[43] = '1.0'; $Script:Files[43] = @(New-TestPendingFiles)
    (Get-WinGetPendingPackageReference @Script:Parameters).PullRequest.number | Should -Be 43
    $Script:PullRequests[42].updated_at = '2026-10-15T01:00:00Z'
    (Get-WinGetPendingPackageReference @Script:Parameters).PullRequest.number | Should -Be 42
  }

  It 'rejects unsafe PRs: <_>' -ForEach @('untrusted', 'closed', 'draft', 'merged', 'wrong-base', 'wrong-repo', 'modified', 'removed', 'unrelated', 'multiple-versions', 'truncated', 'bad-content', 'invalid-schema') {
    switch ($_) {
      untrusted { $Script:PullRequests[42].user.login = 'OtherBot' }
      closed { $Script:PullRequests[42].state = 'closed' }
      draft { $Script:PullRequests[42].draft = $true }
      merged { $Script:PullRequests[42].merged = $true }
      wrong-base { $Script:PullRequests[42].base.ref = 'other' }
      wrong-repo { $Script:PullRequests[42].base.repo.full_name = 'other/winget-pkgs' }
      modified { $Script:Files[42][0].status = 'modified' }
      removed { $Script:Files[42][0].status = 'removed' }
      unrelated { $Script:Files[42][0].filename = 'README.md' }
      multiple-versions { $Script:Files[42][0].filename = 'manifests/v/Vendor/Package/2.0/Vendor.Package.yaml' }
      truncated { $Script:PullRequests[42].changed_files = 4 }
      bad-content { Mock Read-WinGetGitHubManifests -ModuleName WinGetPendingPackage { New-TestPendingContent -Identifier 'Other.Package' } }
      invalid-schema { Mock Read-WinGetGitHubManifests -ModuleName WinGetPendingPackage { $Content = New-TestPendingContent; $Content.Installer = $Content.Installer -replace 'Architecture: x64', 'Architecture: invalid'; $Content } }
    }
    { Get-WinGetPendingPackageReference @Script:Parameters } | Should -Throw '*No trusted open PR*'
  }

  It 'rejects query injection in the trusted-user allowlist before searching' {
    $Script:Parameters.TrustedUser = @('TrustedBot author:Untrusted')
    { Get-WinGetPendingPackageReference @Script:Parameters } | Should -Throw '*Invalid trusted GitHub*'
    Should -Invoke Find-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'does not treat incomplete or failed search results as an absent package' {
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { @{ incomplete_results = $true } }
    { Get-WinGetPendingPackageReference @Script:Parameters } | Should -Throw '*incomplete*'
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { throw 'HTTP 429' }
    { Get-WinGetPendingPackageReference @Script:Parameters } | Should -Throw '*429*'
  }

  It 'warns when recent search results are limited' {
    Mock Find-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { @{ items = @($Script:PullRequests[42]); incomplete_results = $false; total_count = 31 } }
    $null = Get-WinGetPendingPackageReference @Script:Parameters
    $Script:Task.Logs.Where({ $_.Level -eq 'Warning' }).Message | Should -BeLike '*limited to the 30*'
  }

  It 'refuses a PR that moves between metadata and file-list reads' {
    $Script:MetadataReads = 0
    Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage {
      $Script:MetadataReads++
      $Result = New-TestPendingPullRequest
      if ($Script:MetadataReads -gt 1) { $Result.head.sha = 'f' * 40 }
      $Result
    }
    { Get-WinGetPendingPackageReference @Script:Parameters } | Should -Throw '*No trusted open PR*'
    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'rejects a PR that becomes <_> during discovery' -ForEach @('closed', 'merged') {
    $Script:MetadataReads = 0
    $Script:ChangedState = $_
    Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage {
      $Script:MetadataReads++
      $Result = New-TestPendingPullRequest
      if ($Script:MetadataReads -gt 1) {
        if ($Script:ChangedState -eq 'closed') { $Result.state = 'closed' } else { $Result.merged = $true }
      }
      $Result
    }
    { Get-WinGetPendingPackageReference @Script:Parameters } | Should -Throw '*No trusted open PR*'
    Should -Invoke Read-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
  }
}

Describe 'Pending PR updates and exact-content comparison' -Tag Unit {
  BeforeAll {
    $Variable = Get-Variable -Name DumplingsSecret -Scope Global -ErrorAction SilentlyContinue
    $Script:HadDumplingsSecret = $null -ne $Variable
    $Script:OriginalDumplingsSecret = $Variable ? $Variable.Value : $null
  }

  AfterAll {
    if ($Script:HadDumplingsSecret) { $Global:DumplingsSecret = $Script:OriginalDumplingsSecret }
    else { Remove-Variable -Name DumplingsSecret -Scope Global -ErrorAction SilentlyContinue }
  }

  BeforeEach {
    # All credential tests use in-memory fake secrets; never load Secret.yaml.
    $Global:DumplingsSecret = [ordered]@{}
    $Script:Task = New-TestPendingTask
    $Script:Content = New-TestPendingContent
    $Script:Reference = [pscustomobject]@{
      PullRequest = New-TestPendingPullRequest; PackageVersion = '1.0'
      RepoOwner = 'TrustedBot'; RepoName = 'winget-pkgs'; RepoBranch = 'pending-package'; HeadSha = (42).ToString('x40')
      Content = $Script:Content; Manifest = ConvertFrom-WinGetManifestYaml -Content $Script:Content
      Paths = @(New-TestPendingFiles).filename
    }
    $Script:Parameters = @{ Task = $Script:Task; Reference = $Script:Reference; Content = (New-TestPendingContent -Version '2.0'); PackageVersion = '2.0'; Title = 'New package: Vendor.Package version 2.0'; RepoOwner = 'microsoft'; RepoName = 'winget-pkgs'; RootPath = 'manifests' }
    Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { New-TestPendingPullRequest }
    Mock Get-WinGetGitHubPullRequestFile -ModuleName WinGetPendingPackage { New-TestPendingFiles }
    Mock Invoke-GitHubApi -ModuleName WinGetPendingPackage { @{ permissions = @{ push = $true } } }
    Mock Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage { 'c' * 40 }
    Mock Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage {}
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { throw 'Unexpected author-token probe.' }
  }

  It 'atomically adds the new version and removes only the captured pending paths' {
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter {
      $RequireUnchangedHead -and $RepoSha -ceq (42).ToString('x40') -and $RepoOwner -eq 'TrustedBot' -and $RemovePath.Count -eq 3 -and $PackageVersion -eq '2.0'
    }
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter {
      $PullRequestNumber -eq 42 -and $Title -ceq 'New package: Vendor.Package version 2.0' -and $RepoOwner -eq 'microsoft' -and $RepoName -eq 'winget-pkgs'
    }
  }

  It 'rejects a changed or closed PR before any mutation: <_>' -ForEach @('advanced', 'closed', 'merged', 'default-branch', 'no-permission', 'changed-delta') {
    switch ($_) {
      advanced { Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { $Result = New-TestPendingPullRequest; $Result.head.sha = 'f' * 40; $Result } }
      closed { Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { $Result = New-TestPendingPullRequest; $Result.state = 'closed'; $Result } }
      merged { Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { $Result = New-TestPendingPullRequest; $Result.merged = $true; $Result } }
      default-branch { $Script:Reference.RepoBranch = 'master'; Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { $Result = New-TestPendingPullRequest; $Result.head.ref = 'master'; $Result } }
      no-permission { Mock Invoke-GitHubApi -ModuleName WinGetPendingPackage { @{ permissions = @{ push = $false } } } }
      changed-delta { Mock Get-WinGetGitHubPullRequestFile -ModuleName WinGetPendingPackage { $Files = @(New-TestPendingFiles); $Files[0].status = 'modified'; $Files } }
    }
    { Update-WinGetPendingPackagePullRequest @Script:Parameters } | Should -Throw
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'reports partial success when title editing fails after the manifest commit succeeds' {
    Mock Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage { throw 'Title permission denied' }
    { Update-WinGetPendingPackagePullRequest @Script:Parameters } | Should -Throw '*contains the requested manifests*updating its title failed*'
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 1
  }

  It 'retains the normal credential when no author mapping exists: <_>' -ForEach @('standalone', 'null-storage', 'empty-map', 'other-author') {
    switch ($_) {
      standalone { Remove-Variable -Name DumplingsSecret -Scope Global }
      null-storage { $Global:DumplingsSecret = $null }
      empty-map { $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{} }
      other-author { $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ OtherAuthor = 'unused-author-token' } }
    }
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    Should -Invoke Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $null -eq $Token }
  }

  It 'selects the author token case-insensitively and verifies it before committing' {
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens.Add('trustedbot', 'test-author-token')
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens.Add('OtherAuthor', 'unused-author-token')
    $Script:CredentialEvents = [Collections.Generic.List[string]]::new()
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { $Script:CredentialEvents.Add('identity'); @{ login = 'TRUSTEDBOT' } }
    Mock Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage { $Script:CredentialEvents.Add('commit'); 'c' * 40 }
    Mock Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage { $Script:CredentialEvents.Add('title') }
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    $Script:CredentialEvents | Should -Be @('identity', 'commit', 'title')
    Should -Invoke Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $Token -ceq 'test-author-token' }
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $Token -ceq 'test-author-token' }
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $null -eq $Token }
  }

  It 'accepts a SecureString author credential without converting it to plain text' {
    $Script:AuthorToken = [securestring]::new()
    $Script:AuthorToken.AppendChar('x')
    $Script:AuthorToken.MakeReadOnly()
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ TrustedBot = $Script:AuthorToken }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { @{ login = 'TrustedBot' } }
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    Should -Invoke Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { [object]::ReferenceEquals($Token, $Script:AuthorToken) }
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { [object]::ReferenceEquals($Token, $Script:AuthorToken) }
  }

  It 'does not change the shared default credential' {
    $OldToken = $env:GH_DUMPLINGS_TOKEN
    try {
      $env:GH_DUMPLINGS_TOKEN = 'test-normal-bot-token'
      $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ TrustedBot = 'test-author-token' }
      Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { @{ login = 'TrustedBot' } }
      Update-WinGetPendingPackagePullRequest @Script:Parameters
      $env:GH_DUMPLINGS_TOKEN | Should -BeExactly 'test-normal-bot-token'
    } finally { $env:GH_DUMPLINGS_TOKEN = $OldToken }
  }

  It 'rejects a malformed token map before either write: <_>' -ForEach @('string', 'array', 'null') {
    $Map = switch ($_) { string { 'test-malformed-secret' }; array { , @('test-malformed-secret') }; null { $null } }
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = $Map
    { Update-WinGetPendingPackagePullRequest @Script:Parameters } | Should -Throw '*must be a dictionary*'
    Should -Invoke Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'rejects an invalid author token before either write: <_>' -ForEach @('null', 'empty', 'whitespace', 'number', 'array', 'dictionary', 'empty-secure-string') {
    $Value = switch ($_) {
      null { $null }; empty { '' }; whitespace { ' ' }; number { 42 }
      array { , @('test-author-token') }; dictionary { @{ token = 'test-author-token' } }
      empty-secure-string { [securestring]::new() }
    }
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ TrustedBot = $Value }
    { Update-WinGetPendingPackagePullRequest @Script:Parameters } | Should -Throw '*must be a nonempty*'
    Should -Invoke Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'rejects ambiguous differently cased author keys' {
    $Map = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
    $Map.Add('TrustedBot', 'test-first-token')
    $Map.Add('trustedbot', 'test-second-token')
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = $Map
    { Update-WinGetPendingPackagePullRequest @Script:Parameters } | Should -Throw '*ambiguous entries*'
    Should -Invoke Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'rejects the wrong authenticated account before either write' {
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ TrustedBot = 'test-wrong-account-token' }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { @{ login = 'OtherAuthor' } }
    { Update-WinGetPendingPackagePullRequest @Script:Parameters } | Should -Throw '*authenticates as a different account*'
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'redacts a failed identity probe and does not fall back to the bot' {
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ TrustedBot = 'test-sensitive-author-token' }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { throw 'Identity failed: test-sensitive-author-token' }
    $Failure = try { Update-WinGetPendingPackagePullRequest @Script:Parameters } catch { $_ }
    $Failure.Exception.Message | Should -BeLike '*Could not validate*No changes were made*'
    $Failure.Exception.Message | Should -Not -Match 'test-sensitive-author-token'
    $Script:Task.Logs | Should -BeNullOrEmpty
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'redacts mapped-token title failures and preserves the partial-success outcome' {
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ TrustedBot = 'test-sensitive-author-token' }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { @{ login = 'TrustedBot' } }
    Mock Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage { throw 'Title failed: test-sensitive-author-token' }
    $Failure = try { Update-WinGetPendingPackagePullRequest @Script:Parameters } catch { $_ }
    $Failure.Exception.Message | Should -BeLike '*contains the requested manifests*updating its title failed*'
    $Failure.Exception.Message | Should -Not -Match 'test-sensitive-author-token'
    $Script:Task.Logs | Should -BeNullOrEmpty
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 1
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 1
  }

  It 'reconciles a stale title with the author credential without another commit' {
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = @{ TrustedBot = 'test-author-token' }
    Mock Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage { @{ login = 'TrustedBot' } }
    $Script:Parameters.Content = New-TestPendingContent
    $Script:Parameters.PackageVersion = '1.0'
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $Token -ceq 'test-author-token' }
  }

  It 'ignores author credentials when the title is already current' {
    $Global:DumplingsSecret.GitHubPullRequestAuthorTokens = 'unused-malformed-map'
    Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { New-TestPendingPullRequest -Version '2.0' }
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    Should -Invoke Get-WinGetGitHubApiTokenUser -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 1
  }

  It 'repairs a stale title without another manifest commit or push-permission check' {
    $Script:Parameters.Content = New-TestPendingContent
    $Script:Parameters.PackageVersion = '1.0'
    $Script:Parameters.Title = 'New package: Vendor.Package version 1.0'
    Mock Get-WinGetGitHubPullRequest -ModuleName WinGetPendingPackage { $Result = New-TestPendingPullRequest; $Result.title = 'Old title'; $Result }
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Invoke-GitHubApi -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 1 -ParameterFilter { $Title -ceq 'New package: Vendor.Package version 1.0' }
  }

  It 'does not mutate when both manifests and title match' {
    $Script:Parameters.Content = New-TestPendingContent
    $Script:Parameters.PackageVersion = '1.0'
    $Script:Parameters.Title = 'New package: Vendor.Package version 1.0'
    Update-WinGetPendingPackagePullRequest @Script:Parameters
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    Should -Invoke Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage -Exactly 0
  }

  It 'propagates title-only failures without committing or claiming completion' {
    $Script:Parameters.Content = New-TestPendingContent
    $Script:Parameters.PackageVersion = '1.0'
    Mock Set-WinGetGitHubPullRequestTitle -ModuleName WinGetPendingPackage { throw 'Title permission denied' }
    { Update-WinGetPendingPackagePullRequest @Script:Parameters } | Should -Throw '*retry the title without another manifest commit*'
    Should -Invoke Add-WinGetGitHubManifests -ModuleName WinGetPendingPackage -Exactly 0
    $Script:Task.Logs | Should -BeNullOrEmpty
  }

  It 'ignores only line-ending differences and detects changed versions or content' {
    $SameContent = New-TestPendingContent
    $SameContent.Version = $SameContent.Version.ReplaceLineEndings("`r`n")
    Test-WinGetPendingPackageContentEquality -Reference $Script:Reference -Content $SameContent -PackageVersion '1.0' -RootPath manifests | Should -BeTrue
    Test-WinGetPendingPackageContentEquality -Reference $Script:Reference -Content $SameContent -PackageVersion '2.0' -RootPath manifests | Should -BeFalse
    $SameContent.Locale['en-US'] = $SameContent.Locale['en-US'] -replace 'Test package.', 'Changed package.'
    Test-WinGetPendingPackageContentEquality -Reference $Script:Reference -Content $SameContent -PackageVersion '1.0' -RootPath manifests | Should -BeFalse
  }
}
