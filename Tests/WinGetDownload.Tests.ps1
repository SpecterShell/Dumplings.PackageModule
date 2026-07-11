BeforeAll {
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')
}

Describe 'WinGet native download compatibility probe' {
  It 'Builds the installed WinGet WinINet user agent' {
    $UserAgent = Get-WinGetDownloadUserAgent
    $UserAgent | Should -Match '^winget-cli WindowsPackageManager/\d+(?:\.\d+)+ DesktopAppInstaller/Microsoft\.DesktopAppInstaller v\d+(?:\.\d+){3}$'
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
