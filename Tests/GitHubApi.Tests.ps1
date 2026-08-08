# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:GitHubModulePath = Join-Path $PSScriptRoot '..\Libraries\Networking\GitHub.psm1'
  Import-Module $Script:GitHubModulePath -Force
}

Describe 'Invoke-GitHubApi proxy command' {
  It 'exposes the Invoke-RestMethod parameter surface' {
    $RestMethodParameters = (Get-Command Microsoft.PowerShell.Utility\Invoke-RestMethod).Parameters.Keys
    $GitHubParameters = (Get-Command Invoke-GitHubApi).Parameters.Keys

    Compare-Object -ReferenceObject @($RestMethodParameters) -DifferenceObject @($GitHubParameters | Where-Object { $_ -ne 'AllowNonGitHubUri' }) |
      Should -BeNullOrEmpty
    $GitHubParameters | Should -Contain 'AllowNonGitHubUri'
    (Get-Command Invoke-GitHubApi).Parameters.Token.ParameterType | Should -Be ([object])
  }

  It 'prepares an explicit plain-text token, caller headers, and a dictionary body' {
    $Parameters = [ordered]@{
      Uri     = [uri]'https://api.github.com/repos/example/repo'
      Token   = 'test-token'
      Headers = @{ 'X-Test' = 'value'; Accept = 'application/vnd.github.raw+json' }
      Body    = [ordered]@{ name = 'Dumplings'; nested = [ordered]@{ enabled = $true } }
    }

    Initialize-GitHubApiRequest -BoundParameters $Parameters

    $Parameters.Token | Should -BeOfType [securestring]
    $Parameters.Authentication | Should -Be ([Microsoft.PowerShell.Commands.WebAuthenticationType]::Bearer)
    $Parameters.Headers.Accept | Should -BeExactly 'application/vnd.github.raw+json'
    $Parameters.Headers['X-Test'] | Should -BeExactly 'value'
    $Parameters.ContentType | Should -BeExactly 'application/json'
    ($Parameters.Body | ConvertFrom-Json).nested.enabled | Should -BeTrue
  }

  It 'uses GH_DUMPLINGS_TOKEN and supplies the default GitHub media type' {
    $PreviousToken = $Env:GH_DUMPLINGS_TOKEN
    try {
      $Env:GH_DUMPLINGS_TOKEN = 'environment-token'
      $Parameters = [ordered]@{ Uri = [uri]'https://api.github.com/user' }

      Initialize-GitHubApiRequest -BoundParameters $Parameters

      $Parameters.Token | Should -BeOfType [securestring]
      $Parameters.Headers.Accept | Should -BeExactly 'application/vnd.github+json'
    } finally {
      if ($null -eq $PreviousToken) {
        Remove-Item -LiteralPath Env:\GH_DUMPLINGS_TOKEN -ErrorAction SilentlyContinue
      } else {
        $Env:GH_DUMPLINGS_TOKEN = $PreviousToken
      }
    }
  }

  It 'rejects a request without a token' {
    $PreviousToken = $Env:GH_DUMPLINGS_TOKEN
    try {
      Remove-Item -LiteralPath Env:\GH_DUMPLINGS_TOKEN -ErrorAction SilentlyContinue
      { Initialize-GitHubApiRequest -BoundParameters ([ordered]@{ Uri = [uri]'https://api.github.com/user' }) } | Should -Throw '*Core\Index.ps1*-Token*GH_DUMPLINGS_TOKEN*60 requests per hour*'
    } finally {
      if ($null -ne $PreviousToken) { $Env:GH_DUMPLINGS_TOKEN = $PreviousToken }
    }
  }

  It 'accepts the real PSBoundParameters dictionary used by the generated proxy' {
    function Invoke-TestGitHubParameterPreparation {
      [CmdletBinding()]
      param (
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)]$Token,
        [System.Collections.IDictionary]$Body
      )

      Initialize-GitHubApiRequest -BoundParameters $PSBoundParameters
      return $PSBoundParameters
    }

    $Parameters = Invoke-TestGitHubParameterPreparation -Uri 'https://api.github.com/user' -Token 'test-token' -Body @{ value = 1 }

    $Parameters.Token | Should -BeOfType [securestring]
    $Parameters.ContentType | Should -BeExactly 'application/json'
    ($Parameters.Body | ConvertFrom-Json).value | Should -Be 1
  }

  It 'accepts the official GitHub API origin <RequestUri>' -ForEach @(
    @{ RequestUri = 'https://api.github.com/user' }
    @{ RequestUri = 'https://uploads.github.com/repos/example/repo/releases/1/assets' }
  ) {
    $Parameters = [ordered]@{ Uri = [uri]$RequestUri; Token = 'test-token' }

    { Initialize-GitHubApiRequest -BoundParameters $Parameters } | Should -Not -Throw
  }

  It 'rejects the unapproved or ambiguous API origin <RequestUri>' -ForEach @(
    @{ RequestUri = 'https://api.github.com.example.org/user' }
    @{ RequestUri = 'https://github.com/example/repo' }
    @{ RequestUri = 'http://api.github.com/user' }
    @{ RequestUri = 'https://api.github.com:444/user' }
    @{ RequestUri = 'https://user@api.github.com/user' }
  ) {
    $Parameters = [ordered]@{ Uri = [uri]$RequestUri; Token = 'test-token' }

    { Initialize-GitHubApiRequest -BoundParameters $Parameters } | Should -Throw '*unapproved API origin*'
  }

  It 'rejects a non-GitHub origin through the public proxy before making a request' {
    { Invoke-GitHubApi -Uri 'https://example.org/api' -Token 'test-token' } | Should -Throw '*unapproved API origin*'
  }

  It 'allows an explicitly trusted non-GitHub API origin without forwarding the override parameter' {
    $Parameters = [ordered]@{
      Uri               = [uri]'https://github.example.org/api/v3/user'
      Token             = 'test-token'
      AllowNonGitHubUri = $true
    }

    { Initialize-GitHubApiRequest -BoundParameters $Parameters } | Should -Not -Throw
    $Parameters.Contains('AllowNonGitHubUri') | Should -BeFalse
    $Parameters.Token | Should -BeOfType [securestring]
  }

  It 'rejects authorization-preserving redirects unless the origin check is overridden' {
    $Parameters = [ordered]@{
      Uri                             = [uri]'https://api.github.com/user'
      Token                           = 'test-token'
      PreserveAuthorizationOnRedirect = $true
    }

    { Initialize-GitHubApiRequest -BoundParameters $Parameters } | Should -Throw '*preserve GitHub authorization*'
  }
}

Describe 'GitHub API diagnostics' {
  It 'formats GitHub REST status, validation details, documentation, and request ID' {
    $Response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::UnprocessableEntity)
    try {
      $Response.ReasonPhrase = 'Unprocessable Entity'
      $Response.Headers.Add('x-github-request-id', 'REQUEST-123')
      $HttpException = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Response status code does not indicate success.', $Response)
      $ErrorRecord = [System.Management.Automation.ErrorRecord]::new($HttpException, 'GitHubFailure', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
      $ErrorRecord.ErrorDetails = '{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"head","code":"invalid"}],"documentation_url":"https://docs.github.com/rest"}'

      $Exception = ConvertTo-GitHubApiException -ErrorRecord $ErrorRecord -Uri 'https://api.github.com/repos/example/repo/pulls' -Method Post

      $Exception.Message | Should -BeLike '*HTTP 422 Unprocessable Entity*'
      $Exception.Message | Should -BeLike '*Validation Failed*resource=PullRequest, field=head, code=invalid*'
      $Exception.Message | Should -BeLike '*documentation: https://docs.github.com/rest*'
      $Exception.Message | Should -BeLike '*request ID: REQUEST-123*'
    } finally {
      $Response.Dispose()
    }
  }

  It 'formats a GitHub REST payload without validation errors' {
    $Response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Unauthorized)
    try {
      $Response.ReasonPhrase = 'Unauthorized'
      $HttpException = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Response status code does not indicate success.', $Response)
      $ErrorRecord = [System.Management.Automation.ErrorRecord]::new($HttpException, 'GitHubFailure', [System.Management.Automation.ErrorCategory]::AuthenticationError, $null)
      $ErrorRecord.ErrorDetails = '{"message":"Bad credentials","documentation_url":"https://docs.github.com/rest"}'

      $Exception = ConvertTo-GitHubApiException -ErrorRecord $ErrorRecord -Uri 'https://api.github.com/user' -Method Get

      $Exception.Message | Should -BeLike '*HTTP 401 Unauthorized*Bad credentials*'
      $Exception.Message | Should -Not -BeLike '*errors:*'
    } finally {
      $Response.Dispose()
    }
  }

  It 'includes GitHub rate-limit reset and retry evidence' {
    $Response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
    try {
      $Response.ReasonPhrase = 'Too Many Requests'
      $Response.Headers.Add('x-ratelimit-remaining', '0')
      $Response.Headers.Add('x-ratelimit-reset', '1786243200')
      $Response.Headers.Add('retry-after', '30')
      $HttpException = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Response status code does not indicate success.', $Response)
      $ErrorRecord = [System.Management.Automation.ErrorRecord]::new($HttpException, 'GitHubFailure', [System.Management.Automation.ErrorCategory]::LimitsExceeded, $null)
      $ErrorRecord.ErrorDetails = '{"message":"API rate limit exceeded"}'

      $Exception = ConvertTo-GitHubApiException -ErrorRecord $ErrorRecord -Uri 'https://api.github.com/user' -Method Get

      $Exception.Message | Should -BeLike '*HTTP 429 Too Many Requests*rate limit remaining: 0*'
      $Exception.Message | Should -BeLike '*rate limit resets:*UTC*'
      $Exception.Message | Should -BeLike '*retry after: 30 seconds*'
    } finally {
      $Response.Dispose()
    }
  }

  It 'turns GraphQL errors returned with HTTP 200 into a terminating error' {
    $Response = [pscustomobject]@{
      data   = $null
      errors = @([pscustomobject]@{ message = 'Expected head OID does not match'; path = @('createCommitOnBranch') })
    }

    { Write-GitHubApiResponse -InputObject $Response -Uri 'https://api.github.com/graphql' } |
      Should -Throw '*Expected head OID does not match*path: createCommitOnBranch*'
  }

  It 'enumerates top-level JSON arrays for existing callers' {
    $Response = @(
      [pscustomobject]@{ id = 1 }
      [pscustomobject]@{ id = 2 }
    )

    $Result = @(Write-GitHubApiResponse -InputObject $Response -Uri 'https://api.github.com/repos/example/repo/releases')

    $Result.id | Should -Be @(1, 2)
  }
}
