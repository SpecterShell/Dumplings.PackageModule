BeforeAll {
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')
}

Describe 'WinGet native download compatibility probe' {
  It 'Exposes Invoke-WebRequest-compatible timeout and retry parameters' {
    foreach ($Name in @('Invoke-WinGetWinINetDownload', 'Invoke-WinGetDeliveryOptimizationDownload', 'Test-WinGetInstallerDownload')) {
      $Command = Get-Command $Name
      $Command.Parameters.Keys | Should -Contain 'ConnectionTimeoutSeconds'
      $Command.Parameters.Keys | Should -Contain 'OperationTimeoutSeconds'
      $Command.Parameters.Keys | Should -Contain 'MaximumRetryCount'
      $Command.Parameters.Keys | Should -Contain 'RetryIntervalSec'
      $Command.Parameters.Keys | Should -Contain 'MaximumRetryDelaySeconds'
      $Command.Parameters.Keys | Should -Contain 'MaximumTotalRetryDelaySeconds'
      $Command.Parameters['ConnectionTimeoutSeconds'].Aliases | Should -Contain 'TimeoutSec'
    }
  }

  It 'Uses bounded timeout and retry defaults internally' {
    InModuleScope WinGetDownload {
      Mock Invoke-WinGetDownloadOperation {
        [pscustomobject]@{ Success = $true }
      }

      $null = Invoke-WinGetWinINetDownload -Uri 'https://example.com/installer.exe' -DestinationPath $TestDrive -UserAgent 'Dumplings-Test'
      $null = Invoke-WinGetDeliveryOptimizationDownload -Uri 'https://example.com/installer.exe' -DestinationPath $TestDrive

      Should -Invoke Invoke-WinGetDownloadOperation -Exactly 1 -ParameterFilter {
        $Activity -eq 'Downloading installer with WinINet' -and
        $ConnectionTimeoutSeconds -eq 15 -and $OperationTimeoutSeconds -eq 15 -and
        $MaximumRetryCount -eq 3 -and $RetryIntervalSec -eq 3 -and
        $MaximumRetryDelaySeconds -eq 30 -and $MaximumTotalRetryDelaySeconds -eq 60
      }
      Should -Invoke Invoke-WinGetDownloadOperation -Exactly 1 -ParameterFilter {
        $Activity -eq 'Downloading installer with Delivery Optimization' -and
        $ConnectionTimeoutSeconds -eq 15 -and $OperationTimeoutSeconds -eq 15 -and
        $MaximumRetryCount -eq 3 -and $RetryIntervalSec -eq 3 -and
        $MaximumRetryDelaySeconds -eq 30 -and $MaximumTotalRetryDelaySeconds -eq 60
      }
    }
  }

  It 'Formats structured native failure evidence in the C# result layer' {
    $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
    $Result.HttpStatusCode = 503
    $Result.ErrorMessage = 'Synthetic transport failure'
    $Result.FailureStage = 'Finalize'
    $Result.HResult = -2147024891
    $Result.NativeErrorCode = 5

    [Dumplings.WinGetDownload.DownloadFailureFormatter]::Format('WinINet', $Result, $null) |
      Should -BeExactly 'WinINet: HTTP 503; Synthetic transport failure; stage Finalize; HRESULT 0x80070005; native error 5'
  }

  It 'Downloads an installer through Delivery Optimization without invoking WinINet' {
    InModuleScope WinGetDownload {
      $DestinationPath = Join-Path $TestDrive 'delivery-optimization.download'
      Mock Invoke-WinGetDeliveryOptimizationDownload {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1, 2, 3, 4))
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'DeliveryOptimization'
        $Result.Success = $true
        $Result.DestinationPath = $DestinationPath
        $Result
      }
      Mock Invoke-WinGetWinINetDownload { throw 'WinINet should not be called' }

      $Result = Invoke-WinGetInstallerDownload -Uri 'https://example.com/installer.exe' -DestinationPath $DestinationPath

      $Result.DestinationPath | Should -BeExactly $DestinationPath
      $Result.FallbackOccurred | Should -BeFalse
      (Get-Item -LiteralPath $Result.DestinationPath).Length | Should -Be 4
      Should -Invoke Invoke-WinGetDeliveryOptimizationDownload -Exactly 1
      Should -Invoke Invoke-WinGetWinINetDownload -Exactly 0
    }
  }

  It 'Falls back to WinINet after a nonfatal Delivery Optimization failure' {
    InModuleScope WinGetDownload {
      $DestinationPath = Join-Path $TestDrive 'wininet.download'
      Mock Invoke-WinGetDeliveryOptimizationDownload {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](9, 9))
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'DeliveryOptimization'
        $Result.ErrorMessage = 'Synthetic nonfatal failure'
        $Result.DestinationPath = $DestinationPath
        $Result
      }
      Mock Invoke-WinGetWinINetDownload {
        Test-Path -LiteralPath $DestinationPath | Should -BeFalse
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](4, 3, 2, 1))
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'WinINet'
        $Result.Success = $true
        $Result.DestinationPath = $DestinationPath
        $Result
      }

      $FallbackWarnings = $null
      $Result = Invoke-WinGetInstallerDownload -Uri 'https://example.com/installer.exe' -DestinationPath $DestinationPath -WarningVariable FallbackWarnings -WarningAction SilentlyContinue

      $Result.DestinationPath | Should -BeExactly $DestinationPath
      $Result.FallbackOccurred | Should -BeTrue
      $Result.PreviousFailure | Should -BeLike '*Synthetic nonfatal failure*'
      (Get-Item -LiteralPath $Result.DestinationPath).Length | Should -Be 4
      [string]$FallbackWarnings | Should -BeLike '*Synthetic nonfatal failure*Trying WinINet*'
      Should -Invoke Invoke-WinGetDeliveryOptimizationDownload -Exactly 1
      Should -Invoke Invoke-WinGetWinINetDownload -Exactly 1
    }
  }

  It 'Does not bypass a fatal Delivery Optimization policy failure' {
    InModuleScope WinGetDownload {
      $DestinationPath = Join-Path $TestDrive 'fatal-delivery-optimization.download'
      Mock Invoke-WinGetDeliveryOptimizationDownload {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](9, 9))
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'DeliveryOptimization'
        $Result.ErrorMessage = 'Synthetic fatal policy failure'
        $Result.IsFatalDeliveryOptimizationError = $true
        $Result.DestinationPath = $DestinationPath
        $Result
      }
      Mock Invoke-WinGetWinINetDownload { throw 'WinINet must not bypass a fatal Delivery Optimization error' }

      { Invoke-WinGetInstallerDownload -Uri 'https://example.com/installer.exe' -DestinationPath $DestinationPath } | Should -Throw '*fatal Delivery Optimization error*'

      Test-Path -LiteralPath $DestinationPath | Should -BeFalse
      Should -Invoke Invoke-WinGetWinINetDownload -Exactly 0
    }
  }

  It 'Cleans a partial installer when a native download is cancelled' {
    InModuleScope WinGetDownload {
      $DestinationPath = Join-Path $TestDrive 'cancelled.download'
      Mock Invoke-WinGetDeliveryOptimizationDownload {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](9, 9))
        throw [OperationCanceledException]::new('Synthetic cancellation')
      }
      Mock Invoke-WinGetWinINetDownload { throw 'A cancelled pipeline must not start a fallback download' }

      { Invoke-WinGetInstallerDownload -Uri 'https://example.com/installer.exe' -DestinationPath $DestinationPath } | Should -Throw '*Synthetic cancellation*'

      Test-Path -LiteralPath $DestinationPath | Should -BeFalse
      Should -Invoke Invoke-WinGetWinINetDownload -Exactly 0
    }
  }

  It 'Builds the installed WinGet WinINet user agent' {
    $UserAgent = Get-WinGetDownloadUserAgent
    $UserAgent | Should -Match '^winget-cli WindowsPackageManager/\d+(?:\.\d+)+ DesktopAppInstaller/Microsoft\.DesktopAppInstaller v\d+(?:\.\d+){3}$'
  }

  It 'Propagates WinINet timeout values to the native operation' {
    InModuleScope WinGetDownload {
      $script:CapturedArguments = $null
      Mock Open-WinGetWinINetDownloadOperation {
        param($Uri, $DestinationPath, $UserAgent, $Header, $Proxy, $ResponseOnly, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds)
        $script:CapturedArguments = @{
          Uri = $Uri; DestinationPath = $DestinationPath; UserAgent = $UserAgent; Header = $Header; Proxy = $Proxy; ResponseOnly = $ResponseOnly
          ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds; OperationTimeoutSeconds = $OperationTimeoutSeconds
        }
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'WinINet'
        $Result.HttpStatusCode = 200
        $Result.ResponseAccepted = $true
        $Operation = [pscustomobject]@{ IsCompleted = $true; Result = $Result }
        $Operation | Add-Member ScriptMethod Wait { param($Milliseconds) $null = $Milliseconds; return $true }
        $Operation | Add-Member ScriptMethod Cancel { }
        $Operation | Add-Member ScriptMethod Dispose { }
        return $Operation
      }

      $Result = Invoke-WinGetWinINetDownload -Uri 'https://example.com/installer.exe' -DestinationPath $TestDrive `
        -UserAgent 'Dumplings-Test' -ConnectionTimeoutSeconds 17 -OperationTimeoutSeconds 23

      $Result.AttemptCount | Should -Be 1
      $script:CapturedArguments.ConnectionTimeoutSeconds | Should -Be 17
      $script:CapturedArguments.OperationTimeoutSeconds | Should -Be 23
    }
  }

  It 'Propagates Delivery Optimization timeout values to the native operation' {
    InModuleScope WinGetDownload {
      $script:CapturedArguments = $null
      Mock Open-WinGetDeliveryOptimizationDownloadOperation {
        param($Uri, $DestinationPath, $DisplayName, $ExpectedSha256, $Header, $NoProgressTimeoutSeconds, $MaximumDurationSeconds, $ResponseOnly, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds)
        $script:CapturedArguments = @{
          Uri = $Uri; DestinationPath = $DestinationPath; DisplayName = $DisplayName; ExpectedSha256 = $ExpectedSha256; Header = $Header
          NoProgressTimeoutSeconds = $NoProgressTimeoutSeconds; MaximumDurationSeconds = $MaximumDurationSeconds; ResponseOnly = $ResponseOnly
          ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds; OperationTimeoutSeconds = $OperationTimeoutSeconds
        }
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'DeliveryOptimization'
        $Result.HttpStatusCode = 206
        $Result.ResponseAccepted = $true
        $Operation = [pscustomobject]@{ IsCompleted = $true; Result = $Result }
        $Operation | Add-Member ScriptMethod Wait { param($Milliseconds) $null = $Milliseconds; return $true }
        $Operation | Add-Member ScriptMethod Cancel { }
        $Operation | Add-Member ScriptMethod Dispose { }
        return $Operation
      }

      $Result = Invoke-WinGetDeliveryOptimizationDownload -Uri 'https://example.com/installer.exe' -DestinationPath $TestDrive `
        -ConnectionTimeoutSeconds 19 -OperationTimeoutSeconds 29 -NoProgressTimeoutSeconds 31 -MaximumDurationSeconds 37 -ResponseOnly

      $Result.AttemptCount | Should -Be 1
      $script:CapturedArguments.ConnectionTimeoutSeconds | Should -Be 19
      $script:CapturedArguments.OperationTimeoutSeconds | Should -Be 29
      $script:CapturedArguments.NoProgressTimeoutSeconds | Should -Be 31
      $script:CapturedArguments.MaximumDurationSeconds | Should -Be 37
    }
  }

  It 'Retries retryable statuses and honors integer Retry-After for HTTP 429' {
    InModuleScope WinGetDownload {
      $script:NativeAttempt = 0
      Mock Start-Sleep { }
      Mock Open-WinGetWinINetDownloadOperation {
        $script:NativeAttempt++
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'WinINet'
        if ($script:NativeAttempt -eq 1) {
          $Result.HttpStatusCode = 429
          $Result.ResponseHeaders = "HTTP/1.1 429 Too Many Requests`r`nRetry-After: 7`r`n"
        } else {
          $Result.HttpStatusCode = 200
          $Result.ResponseAccepted = $true
          $Result.Success = $true
        }
        $Operation = [pscustomobject]@{ IsCompleted = $true; Result = $Result }
        $Operation | Add-Member ScriptMethod Wait { param($Milliseconds) $null = $Milliseconds; return $true }
        $Operation | Add-Member ScriptMethod Cancel { }
        $Operation | Add-Member ScriptMethod Dispose { }
        return $Operation
      }

      $Result = Invoke-WinGetWinINetDownload -Uri 'https://example.com/installer.exe' -DestinationPath $TestDrive `
        -UserAgent 'Dumplings-Test' -MaximumRetryCount 1 -RetryIntervalSec 2

      $Result.Success | Should -BeTrue
      $Result.AttemptCount | Should -Be 2
      Should -Invoke Open-WinGetWinINetDownloadOperation -Times 2
      Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 7 }
    }
  }

  It 'Parses HTTP-date Retry-After values' {
    InModuleScope WinGetDownload {
      $Now = [datetimeoffset]'2026-07-17T12:00:00Z'
      $RetryDate = $Now.AddSeconds(12).ToString('R', [Globalization.CultureInfo]::InvariantCulture)
      $Result = [pscustomobject]@{
        HttpStatusCode = 429
        ResponseHeaders = "HTTP/1.1 429 Too Many Requests`r`nRetry-After: $RetryDate`r`n"
      }

      Get-WinGetDownloadRetryInterval -Result $Result -DefaultSeconds 3 -UtcNow $Now | Should -Be 12
    }
  }

  It 'Stops retrying when Retry-After exceeds the per-retry delay limit' {
    InModuleScope WinGetDownload {
      Mock Start-Sleep { }
      Mock Open-WinGetWinINetDownloadOperation {
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'WinINet'
        $Result.HttpStatusCode = 429
        $Result.ResponseHeaders = "HTTP/1.1 429 Too Many Requests`r`nRetry-After: 3600`r`n"
        $Operation = [pscustomobject]@{ IsCompleted = $true; Result = $Result }
        $Operation | Add-Member ScriptMethod Wait { param($Milliseconds) $null = $Milliseconds; return $true }
        $Operation | Add-Member ScriptMethod Cancel { }
        $Operation | Add-Member ScriptMethod Dispose { }
        return $Operation
      }

      $Result = Invoke-WinGetWinINetDownload -Uri 'https://example.com/installer.exe' -DestinationPath $TestDrive `
        -UserAgent 'Dumplings-Test' -MaximumRetryCount 3 -MaximumRetryDelaySeconds 30 -MaximumTotalRetryDelaySeconds 60

      $Result.HttpStatusCode | Should -Be 429
      $Result.AttemptCount | Should -Be 1
      Should -Invoke Open-WinGetWinINetDownloadOperation -Times 1
      Should -Invoke Start-Sleep -Times 0
    }
  }

  It 'Stops retrying before exceeding the cumulative retry-delay budget' {
    InModuleScope WinGetDownload {
      Mock Start-Sleep { }
      Mock Open-WinGetWinINetDownloadOperation {
        $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        $Result.Method = 'WinINet'
        $Result.HttpStatusCode = 503
        $Operation = [pscustomobject]@{ IsCompleted = $true; Result = $Result }
        $Operation | Add-Member ScriptMethod Wait { param($Milliseconds) $null = $Milliseconds; return $true }
        $Operation | Add-Member ScriptMethod Cancel { }
        $Operation | Add-Member ScriptMethod Dispose { }
        return $Operation
      }

      $Result = Invoke-WinGetWinINetDownload -Uri 'https://example.com/installer.exe' -DestinationPath $TestDrive `
        -UserAgent 'Dumplings-Test' -MaximumRetryCount 3 -RetryIntervalSec 3 `
        -MaximumRetryDelaySeconds 30 -MaximumTotalRetryDelaySeconds 5

      $Result.HttpStatusCode | Should -Be 503
      $Result.AttemptCount | Should -Be 2
      Should -Invoke Open-WinGetWinINetDownloadOperation -Times 2
      Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 3 }
    }
  }

  It 'Writes progress and cancels the native operation after a terminating interruption' {
    InModuleScope WinGetDownload {
      Mock Write-Progress { }
      $Result = [Dumplings.WinGetDownload.DownloadResult]::new()
      $Operation = [pscustomobject]@{
        IsCompleted = $false
        Result = $Result
        WaitCount = 0
        CancelCount = 0
        DisposeCount = 0
      }
      $Operation | Add-Member ScriptMethod Wait {
        param($Milliseconds)
        $null = $Milliseconds
        $this.WaitCount++
        if ($this.WaitCount -eq 1) { [Threading.Thread]::Sleep(1100); return $false }
        throw [InvalidOperationException]::new('Simulated pipeline interruption')
      }
      $Operation | Add-Member ScriptMethod GetProgress {
        [pscustomobject]@{ BytesDownloaded = 524288; ContentLength = 1048576; State = 'Downloading' }
      }
      $Operation | Add-Member ScriptMethod Cancel { $this.CancelCount++ }
      $Operation | Add-Member ScriptMethod Dispose { $this.DisposeCount++ }

      {
        Invoke-WinGetDownloadOperation -StartOperation { param($Attempt, $Argument) $null = $Attempt; $Argument.Operation } `
          -OperationArgument @{ Operation = $Operation } -Activity 'Test download'
      } | Should -Throw '*Simulated pipeline interruption*'

      $Operation.CancelCount | Should -Be 1
      $Operation.DisposeCount | Should -Be 1
      Should -Invoke Write-Progress -Times 1 -ParameterFilter { -not $Completed -and $PercentComplete -eq 50 }
      Should -Invoke Write-Progress -Times 1 -ParameterFilter { $Completed }
    }
  }

  It 'Cancels a native operation when the connection watchdog expires' {
    InModuleScope WinGetDownload {
      Mock Write-Progress { }
      $Operation = [pscustomobject]@{
        IsCompleted = $false
        Result = [Dumplings.WinGetDownload.DownloadResult]::new()
        CancelCount = 0
        DisposeCount = 0
      }
      $Operation | Add-Member ScriptMethod Wait { param($Milliseconds) [Threading.Thread]::Sleep($Milliseconds); return $false }
      $Operation | Add-Member ScriptMethod GetProgress { [pscustomobject]@{ BytesDownloaded = 0; ContentLength = $null; State = 'Connecting' } }
      $Operation | Add-Member ScriptMethod Cancel { $this.CancelCount++ }
      $Operation | Add-Member ScriptMethod Dispose { $this.DisposeCount++ }

      {
        Invoke-WinGetDownloadOperation -StartOperation { param($Attempt, $Argument) $null = $Attempt; $Argument.Operation } `
          -OperationArgument @{ Operation = $Operation } -Activity 'Test download' -ConnectionTimeoutSeconds 1
      } | Should -Throw '*exceeded the 1-second connection timeout*'

      $Operation.CancelCount | Should -BeGreaterOrEqual 1
      $Operation.DisposeCount | Should -Be 1
    }
  }

  It 'Falls back from a nonfatal Delivery Optimization failure to WinINet' {
    InModuleScope WinGetDownload {
      Mock Get-WinGetDownloadUserAgent { 'winget-cli WindowsPackageManager/1.2.3 DesktopAppInstaller/Microsoft.DesktopAppInstaller v1.2.3.0' }
      Mock Invoke-WinGetDeliveryOptimizationDownload {
        [pscustomobject]@{ Method = 'DeliveryOptimization'; Success = $false; ResponseAccepted = $false; Sha256 = $null; DestinationPath = $DestinationPath; IsFatalDeliveryOptimizationError = $false }
      }
      Mock Invoke-WinGetWinINetDownload {
        [pscustomobject]@{ Method = 'WinINet'; Success = $true; ResponseAccepted = $true; Sha256 = 'A' * 64; DestinationPath = $DestinationPath; IsFatalDeliveryOptimizationError = $false }
      }

      $Result = Test-WinGetInstallerDownload -Uri 'https://example.com/installer.exe' -ExpectedSha256 ('A' * 64)
      $Result.FallbackOccurred | Should -BeTrue
      $Result.EffectiveMethod | Should -Be 'WinINet'
      $Result.WouldWinGetDownload | Should -BeTrue
      $Result.Results.Method | Should -Be @('DeliveryOptimization', 'WinINet')
    }
  }

  It 'Does not bypass fatal Delivery Optimization policy errors' {
    InModuleScope WinGetDownload {
      Mock Get-WinGetDownloadUserAgent { 'winget-cli WindowsPackageManager/1.2.3 DesktopAppInstaller/Microsoft.DesktopAppInstaller v1.2.3.0' }
      Mock Invoke-WinGetDeliveryOptimizationDownload {
        [pscustomobject]@{ Method = 'DeliveryOptimization'; Success = $false; ResponseAccepted = $false; Sha256 = $null; DestinationPath = $DestinationPath; IsFatalDeliveryOptimizationError = $true }
      }
      Mock Invoke-WinGetWinINetDownload { throw 'WinINet must not be called for a fatal DO policy error.' }

      $Result = Test-WinGetInstallerDownload -Uri 'https://example.com/installer.exe'
      $Result.FallbackOccurred | Should -BeFalse
      $Result.EffectiveMethod | Should -Be 'DeliveryOptimization'
      $Result.WouldWinGetDownload | Should -BeFalse
      Should -Invoke Invoke-WinGetWinINetDownload -Times 0
    }
  }

  It 'Treats a response-only DO transfer as accepted without falling back' {
    InModuleScope WinGetDownload {
      Mock Get-WinGetDownloadUserAgent { 'winget-cli WindowsPackageManager/1.2.3 DesktopAppInstaller/Microsoft.DesktopAppInstaller v1.2.3.0' }
      Mock Invoke-WinGetDeliveryOptimizationDownload {
        [pscustomobject]@{ Method = 'DeliveryOptimization'; Success = $false; ResponseAccepted = $true; Sha256 = $null; DestinationPath = $DestinationPath; IsFatalDeliveryOptimizationError = $false; HttpStatusCode = 206 }
      }
      Mock Invoke-WinGetWinINetDownload { throw 'An accepted DO response must not fall back in response-only mode.' }

      $Result = Test-WinGetInstallerDownload -Uri 'https://example.com/installer.exe' -ResponseOnly
      $Result.ServerAcceptedRequest | Should -BeTrue
      $Result.WouldWinGetDownload | Should -BeFalse
      $Result.FallbackOccurred | Should -BeFalse
      Should -Invoke Invoke-WinGetWinINetDownload -Times 0
    }
  }

  It 'Forces WinINet when an explicit proxy is configured' {
    InModuleScope WinGetDownload {
      Mock Get-WinGetDownloadUserAgent { 'winget-cli WindowsPackageManager/1.2.3 DesktopAppInstaller/Microsoft.DesktopAppInstaller v1.2.3.0' }
      Mock Invoke-WinGetDeliveryOptimizationDownload { throw 'Delivery Optimization must not be used with a proxy.' }
      Mock Invoke-WinGetWinINetDownload {
        [pscustomobject]@{ Method = 'WinINet'; Success = $false; ResponseAccepted = $false; Sha256 = $null; DestinationPath = $DestinationPath; IsFatalDeliveryOptimizationError = $false }
      }

      $Result = Test-WinGetInstallerDownload -Uri 'https://example.com/installer.exe' -Proxy 'http://127.0.0.1:8080'
      $Result.ProxyForcedWinINet | Should -BeTrue
      $Result.EffectiveMethod | Should -Be 'WinINet'
      Should -Invoke Invoke-WinGetDeliveryOptimizationDownload -Times 0
    }
  }
}
