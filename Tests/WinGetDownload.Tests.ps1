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
      $Command.Parameters['ConnectionTimeoutSeconds'].Aliases | Should -Contain 'TimeoutSec'
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
