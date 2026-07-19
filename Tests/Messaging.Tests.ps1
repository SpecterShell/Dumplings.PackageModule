# SPDX-License-Identifier: Apache-2.0

BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\TextContent.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Messaging.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Telegram.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Matrix.psm1') -Force
}

Describe 'Shared message splitting' {
  It 'packs complete lines before splitting an oversized line' {
    $Message = "alpha`nbeta`ngamma`n" + ('delta ' * 10)
    $Chunks = @(Split-MessageText -Message $Message -MaximumLength 20 -LengthMode UTF16 -Format PlainText)

    $Chunks.Count | Should -BeGreaterThan 2
    $Chunks[0] | Should -BeExactly "alpha`nbeta`ngamma`n"
    foreach ($Chunk in $Chunks) { $Chunk.Length | Should -BeLessOrEqual 20 }
  }

  It 'keeps emoji and combining sequences on grapheme boundaries' {
    $Message = ('😀' * 12) + ('e' + [char]0x0301) * 12
    $Chunks = @(Split-MessageText -Message $Message -MaximumLength 16 -LengthMode UTF16 -Format PlainText)

    ($Chunks -join '') | Should -BeExactly $Message
    foreach ($Chunk in $Chunks) {
      $Chunk.Length | Should -BeLessOrEqual 16
      $Chunk | Should -Not -Match "^$([char]0x0301)"
      $Chunk | Should -Not -Match "$([char]0xD83D)$"
    }
  }

  It 'closes and reopens fenced Markdown code blocks' {
    $Message = @'
before
```powershell
Write-Host one
Write-Host two
Write-Host three
Write-Host four
```
after
'@
    $Chunks = @(Split-MessageText -Message $Message -MaximumLength 48 -LengthMode UTF16 -Format MarkdownV2)

    $Chunks.Count | Should -BeGreaterThan 1
    foreach ($Chunk in $Chunks) {
      $Chunk.Length | Should -BeLessOrEqual 48
      ([regex]::Matches($Chunk, '```').Count % 2) | Should -Be 0
    }
    $Chunks[1] | Should -Match '^```powershell\n'
  }

  It 'sanitizes and emits balanced HTML chunks' {
    $Html = '<p>Hello <strong>world and a longer line</strong></p><p><a href="javascript:alert(1)">unsafe</a><script>bad()</script> 😀😀😀😀</p>'
    $Chunks = @(Split-HtmlMessage -Html $Html -MaximumLength 18 -LengthMode UTF16 -HtmlProfile Matrix)

    $Chunks.Count | Should -BeGreaterThan 1
    ($Chunks -join '') | Should -Not -Match 'script|javascript'
    foreach ($Chunk in $Chunks) {
      $Document = $Chunk | ConvertFrom-Html
      $Document.OuterHtml | Should -Not -BeNullOrEmpty
      $PlainText = $Document | Get-TextContent
      (Get-MessageTextLength -Text $PlainText -LengthMode UTF16) | Should -BeLessOrEqual 18
      ([regex]::Matches($Chunk, '<strong>').Count) | Should -Be ([regex]::Matches($Chunk, '</strong>').Count)
    }
  }
}

Describe 'Telegram messaging' {
  InModuleScope Telegram {
    It 'preserves the complete text of a single Markdown chunk' {
      $script:WrittenMessage = $null
      Mock Invoke-TelegramMessageWrite {
        param($Message)
        $script:WrittenMessage = $Message
        [pscustomobject]@{
          Response    = [pscustomobject]@{ result = [pscustomobject]@{ message_id = 100 } }
          SentText    = $Message
          NotModified = $false
        }
      }

      $Message = "*Example\.Package*`n`n*Version:* 1\.2\.3"
      $null = Send-TelegramMessage -Message $Message -AsMarkdown -ChatID 'chat' -Token 'token'

      $script:WrittenMessage | Should -BeExactly $Message
    }

    It 'reconciles line-split chunks without changing the session type' {
      $script:NextMessageID = 100
      $script:Writes = [System.Collections.Generic.List[object]]::new()
      Mock Invoke-TelegramMessageWrite {
        param($Operation, $Message)
        $script:Writes.Add([pscustomobject]@{ Operation = $Operation; Message = $Message })
        [pscustomobject]@{
          Response    = [pscustomobject]@{ result = [pscustomobject]@{ message_id = $script:NextMessageID++ } }
          SentText    = $Message
          NotModified = $false
        }
      }
      Mock Remove-TelegramMessage { [pscustomobject]@{ ok = $true } }

      $Session = [System.Collections.Generic.List[System.Tuple[string, long]]]::new()
      $Result = Send-TelegramMessage -Message ((1..12 | ForEach-Object { "line-${_}" }) -join "`n") `
        -Session $Session -ChatID 'chat' -Token 'token' -MaximumMessageLength 24

      $Result.GetType() | Should -Be $Session.GetType()
      [object]::ReferenceEquals($Result, $Session) | Should -BeTrue
      $Session.Count | Should -BeGreaterThan 1
      foreach ($Write in $script:Writes) {
        $Write.Message.Length | Should -BeLessOrEqual 24
        $Write.Message | Should -Not -Match '^ne-'
      }
    }

    It 'ignores only the exact message-not-modified error' {
      Mock Update-TelegramMessage {
        throw (Get-TelegramApiException -ErrorCode 400 -Description 'Bad Request: message is not modified')
      }

      $Result = Invoke-TelegramMessageWrite -Operation Update -Message 'same' -MessageID 7 -ChatID 'chat' -Token 'token'
      $Result.NotModified | Should -BeTrue
      $Result.SentText | Should -BeExactly 'same'
    }

    It 'does not suppress unrelated HTTP 400 responses' {
      Mock Update-TelegramMessage {
        throw (Get-TelegramApiException -ErrorCode 400 -Description 'Bad Request: chat not found')
      }

      { Invoke-TelegramMessageWrite -Operation Update -Message 'text' -MessageID 7 -ChatID 'chat' -Token 'token' } |
        Should -Throw '*chat not found*'
    }

    It 'falls back from rejected MarkdownV2 to plain text once' {
      $script:UpdateAttempts = 0
      Mock Update-TelegramMessage {
        param($Message, $AsMarkdown)
        $script:UpdateAttempts++
        if ($AsMarkdown) { throw (Get-TelegramApiException -ErrorCode 400 -Description "Bad Request: can't parse entities") }
        [pscustomobject]@{ ok = $true; result = [pscustomobject]@{ message_id = 7 }; text = $Message }
      }

      $Result = Invoke-TelegramMessageWrite -Operation Update -Message '*bold* and escaped\.' -MessageID 7 `
        -AsMarkdown -ChatID 'chat' -Token 'token'

      $script:UpdateAttempts | Should -Be 2
      $Result.SentText | Should -BeExactly 'bold and escaped.'
    }

    It 'does not retry an ambiguous sendMessage transport failure and redacts the token' {
      Mock Invoke-RestMethod { throw 'request to https://api.telegram.org/botsecret-token/sendMessage failed' }

      try {
        $null = Invoke-TelegramApi -Method sendMessage -Body @{ chat_id = 'chat'; text = 'test' } `
          -Token 'secret-token' -MaximumRetryCount 3
        throw 'Expected Invoke-TelegramApi to fail'
      } catch {
        $_.Exception.Message | Should -Not -Match 'secret-token'
        $_.Exception.Message | Should -Match '<redacted>'
      }
      Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'rejects server retry delays beyond the configured bound' {
      Mock Invoke-RestMethod {
        [pscustomobject]@{
          ok          = $false
          error_code  = 429
          description = 'Too Many Requests'
          parameters  = [pscustomobject]@{ retry_after = 600 }
        }
      }
      Mock Start-Sleep

      { Invoke-TelegramApi -Method sendMessage -Body @{ chat_id = 'chat'; text = 'test' } -Token 'token' -MaximumRetryDelaySeconds 30 } |
        Should -Throw '*exceeds the configured limit*'
      Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'delegates Telegram Retry-After delays to the shared target limiter' {
      $Context = [pscustomobject]@{
        MaximumRetryDelaySeconds      = 30
        MaximumTotalRetryDelaySeconds = 60
        WaitCount                     = 0
        MarkCount                     = 0
        RetryDelays                   = [Collections.Generic.List[timespan]]::new()
      }
      $Context | Add-Member -MemberType ScriptMethod -Name Wait -Value { $this.WaitCount++ }
      $Context | Add-Member -MemberType ScriptMethod -Name MarkAttemptCompleted -Value { $this.MarkCount++ }
      $Context | Add-Member -MemberType ScriptMethod -Name SetRetryAfter -Value { param ($Delay) $this.RetryDelays.Add($Delay) }
      $script:Attempt = 0
      Mock Invoke-RestMethod {
        if ($script:Attempt++ -eq 0) {
          return [pscustomobject]@{
            ok = $false; error_code = 429; description = 'Too Many Requests'
            parameters = [pscustomobject]@{ retry_after = 7 }
          }
        }
        [pscustomobject]@{ ok = $true; result = [pscustomobject]@{ message_id = 1 } }
      }
      Mock Start-Sleep

      $null = Invoke-TelegramApi -Method sendMessage -Body @{ chat_id = 'chat'; text = 'test' } -Token 'token' `
        -MaximumRetryCount 1 -RateLimitContext $Context

      $Context.WaitCount | Should -Be 2
      $Context.MarkCount | Should -Be 2
      $Context.RetryDelays.Count | Should -Be 1
      $Context.RetryDelays[0].TotalSeconds | Should -Be 7
      Should -Invoke Start-Sleep -Times 0 -Exactly
    }
  }
}

Describe 'Matrix messaging' {
  InModuleScope Matrix {
    It 'preserves the complete text of a single Markdown chunk' {
      Mock Assert-MatrixPlaintextAllowed
      $script:WrittenMessage = $null
      Mock Invoke-MatrixMessageWrite {
        param($Message)
        $script:WrittenMessage = $Message
        [pscustomobject]@{ event_id = '$event' }
      }

      $Message = "**Example.Package**`n`n**Version:** 1.2.3"
      $null = Send-MatrixMessage -Message $Message -AsMarkdown -RoomID '!room:example.org' `
        -HomeServer 'https://example.org' -Token 'token'

      $script:WrittenMessage | Should -BeExactly $Message
    }

    It 'detects encrypted and unencrypted room state without hard-coded room identities' {
      Mock Invoke-MatrixApi { [pscustomobject]@{ algorithm = 'm.megolm.v1.aes-sha2' } }
      Test-MatrixRoomEncrypted -RoomID '!room:example.org' -HomeServer 'https://example.org' -Token 'token' | Should -BeTrue

      Mock Invoke-MatrixApi { [pscustomobject]@{ errcode = 'M_NOT_FOUND'; error = 'Not found' } }
      Test-MatrixRoomEncrypted -RoomID '!other:example.org' -HomeServer 'https://example.org' -Token 'token' | Should -BeFalse
    }

    It 'fails closed for encrypted rooms unless the explicit plaintext override is used' {
      Mock Test-MatrixRoomEncrypted { $true }

      { Assert-MatrixPlaintextAllowed -RoomID '!room:example.org' -HomeServer 'https://example.org' -Token 'token' } |
        Should -Throw '*refusing to send plaintext*'
      { Assert-MatrixPlaintextAllowed -RoomID '!room:example.org' -HomeServer 'https://example.org' -Token 'token' `
          -AllowUnencryptedInEncryptedRoom -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'creates spec-compatible replacement fallback content' {
      $Content = ConvertTo-MatrixMessageContent -Message "**bold**`nnext" -Format Markdown -EditEventID '$event'

      $Content.body | Should -BeExactly "* bold`nnext"
      $Content.'m.new_content'.body | Should -BeExactly "bold`nnext"
      $Content.formatted_body | Should -Match '^\* '
      $Content.'m.new_content'.formatted_body | Should -Not -Match '^\* '
      $Content.'m.relates_to'.rel_type | Should -BeExactly 'm.replace'
    }

    It 'reconciles a mutable multi-event session' {
      Mock Assert-MatrixPlaintextAllowed
      $script:NewEvent = 0
      Mock Invoke-MatrixMessageWrite {
        param($Operation)
        if ($Operation -eq 'New') { return [pscustomobject]@{ event_id = "`$new-$($script:NewEvent++)" } }
        [pscustomobject]@{ event_id = '$edit' }
      }
      Mock Remove-MatrixMessage { [pscustomobject]@{ event_id = '$redaction' } }

      $Session = [System.Collections.Generic.List[System.Tuple[string, string]]]::new()
      $Result = Send-MatrixMessage -Message ((1..12 | ForEach-Object { "line-${_}" }) -join "`n") `
        -Session $Session -RoomID '!room:example.org' -HomeServer 'https://example.org' -Token 'token' -MaximumMessageLength 24

      [object]::ReferenceEquals($Result, $Session) | Should -BeTrue
      $Session.Count | Should -BeGreaterThan 1
      $Session[0].Item2 | Should -BeLike '$new-*'
    }

    It 'returns scalar compatibility for a single event and arrays for split messages' {
      Mock Assert-MatrixPlaintextAllowed
      $script:NewEvent = 0
      Mock Invoke-MatrixMessageWrite {
        $EventNumber = $script:NewEvent
        $script:NewEvent++
        [pscustomobject]@{ event_id = "`$event-${EventNumber}" }
      }

      (Send-MatrixMessage -Message 'short' -RoomID '!room:example.org' -HomeServer 'https://example.org' -Token 'token') |
        Should -BeExactly '$event-0'
      $Result = Send-MatrixMessage -Message ('line' * 20) -RoomID '!room:example.org' `
        -HomeServer 'https://example.org' -Token 'token' -MaximumMessageLength 16
      $Result.GetType().FullName | Should -BeExactly 'System.String[]'
      $Result.Count | Should -BeGreaterThan 1
    }

    It 'reuses one GUID transaction ID across a transient retry' {
      $script:Uris = [System.Collections.Generic.List[string]]::new()
      $script:Attempt = 0
      Mock Invoke-RestMethod {
        param($Uri)
        $script:Uris.Add([string]$Uri)
        if ($script:Attempt++ -eq 0) { throw 'temporary network failure' }
        [pscustomobject]@{ event_id = '$event' }
      }
      Mock Start-Sleep

      $null = Invoke-MatrixApi -EndPoint '/_matrix/client/v3/rooms/room/send/m.room.message' -Method Put `
        -Body @{ msgtype = 'm.text'; body = 'test' } -HomeServer 'https://example.org/' -Token 'token' -MaximumRetryCount 1

      $script:Uris.Count | Should -Be 2
      $script:Uris[0] | Should -BeExactly $script:Uris[1]
      $script:Uris[0] | Should -Match '/[0-9a-f]{32}$'
    }

    It 'URI-escapes room and event IDs before sending or redacting' {
      Mock Invoke-MatrixApi { [pscustomobject]@{ event_id = '$event' } }

      $null = Invoke-MatrixMessageWrite -Operation New -Message 'test' -Format PlainText `
        -RoomID '!room:example.org' -HomeServer 'https://example.org' -Token 'token'
      $null = Remove-MatrixMessage -EventID '$event:example.org' -RoomID '!room:example.org' `
        -HomeServer 'https://example.org' -Token 'token'

      Should -Invoke Invoke-MatrixApi -ParameterFilter { $EndPoint -match '%21room%3Aexample\.org' } -Times 2
      Should -Invoke Invoke-MatrixApi -ParameterFilter { $EndPoint -match '%24event%3Aexample\.org' } -Times 1
    }

    It 'delegates Matrix rate limits to the shared target limiter' {
      $Context = [pscustomobject]@{
        MaximumRetryDelaySeconds      = 30
        MaximumTotalRetryDelaySeconds = 60
        WaitCount                     = 0
        MarkCount                     = 0
        RetryDelays                   = [Collections.Generic.List[timespan]]::new()
      }
      $Context | Add-Member -MemberType ScriptMethod -Name Wait -Value { $this.WaitCount++ }
      $Context | Add-Member -MemberType ScriptMethod -Name MarkAttemptCompleted -Value { $this.MarkCount++ }
      $Context | Add-Member -MemberType ScriptMethod -Name SetRetryAfter -Value { param ($Delay) $this.RetryDelays.Add($Delay) }
      $script:Attempt = 0
      Mock Invoke-RestMethod {
        if ($script:Attempt++ -eq 0) {
          return [pscustomobject]@{ errcode = 'M_LIMIT_EXCEEDED'; error = 'Slow down'; retry_after_ms = 2500 }
        }
        [pscustomobject]@{ event_id = '$event' }
      }
      Mock Start-Sleep

      $null = Invoke-MatrixApi -EndPoint '/_matrix/client/v3/rooms/room/send/m.room.message' -Method Put `
        -Body @{ msgtype = 'm.text'; body = 'test' } -HomeServer 'https://example.org' -Token 'token' `
        -MaximumRetryCount 1 -RateLimitContext $Context

      $Context.WaitCount | Should -Be 2
      $Context.MarkCount | Should -Be 2
      $Context.RetryDelays.Count | Should -Be 1
      $Context.RetryDelays[0].TotalSeconds | Should -Be 3
      Should -Invoke Start-Sleep -Times 0 -Exactly
    }
  }
}
