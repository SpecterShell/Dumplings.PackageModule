. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\WinGetManifestTestSetup.ps1')

Describe 'Get-WinGetInstallerReleaseDate' -Tag Unit {
  InModuleScope WinGetManifestUpdate {
    BeforeEach {
      $Script:InstallerPath = Join-Path $TestDrive 'installer.exe'
      $Script:InstallerUrl = 'https://example.test/installer.exe'
      $Script:LogMessages = [System.Collections.Generic.List[object]]::new()
      $Script:Logger = { param($Message, $Level) $Script:LogMessages.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
    }

    It 'reads Last-Modified from the fresh download response headers' {
      $DownloadResult = [pscustomobject]@{
        HttpStatusCode  = 200
        FinalUri        = $null
        ResponseHeaders = "HTTP/1.1 200 OK`r`nContent-Length: 100`r`nLast-Modified: Wed, 15 Jul 2026 08:30:00 GMT`r`n"
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl -DownloadResult $DownloadResult | Should -Be '2026-07-15'
    }

    It 'returns null when the download response has no Last-Modified header' {
      $DownloadResult = [pscustomobject]@{
        HttpStatusCode  = 200
        FinalUri        = $null
        ResponseHeaders = "HTTP/1.1 200 OK`r`nContent-Length: 100`r`n"
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl -DownloadResult $DownloadResult | Should -BeNullOrEmpty
    }

    It 'returns null for an invalid HTTP date' {
      $DownloadResult = [pscustomobject]@{
        HttpStatusCode  = 200
        FinalUri        = $null
        ResponseHeaders = "HTTP/1.1 200 OK`r`nLast-Modified: not-a-date`r`n"
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl -DownloadResult $DownloadResult | Should -BeNullOrEmpty
    }

    It 'falls back to a header request when no download response is available' {
      Mock Get-WebResponseHeader -ModuleName WinGetManifestUpdate {
        $Headers = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
        $Headers['Last-Modified'] = [string[]]@('Tue, 01 Jul 2025 12:00:00 GMT')
        [pscustomobject]@{ Headers = $Headers }
      }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl | Should -Be '2025-07-01'
    }

    It 'returns null when the header request fails' {
      Mock Get-WebResponseHeader -ModuleName WinGetManifestUpdate { throw 'The remote name could not be resolved' }

      Get-WinGetInstallerReleaseDate -Uri $Script:InstallerUrl | Should -BeNullOrEmpty
    }

    It 'ignores non-HTTP installer URLs' {
      Get-WinGetInstallerReleaseDate -Uri 'ftp://example.test/installer.exe' | Should -BeNullOrEmpty
    }

    It 'Fills a missing ReleaseDate from the download Last-Modified header' {
      Mock Invoke-WinGetInstallerDownload -ModuleName WinGetManifestUpdate {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1, 2, 3, 4))
        [pscustomobject]@{
          DestinationPath = $DestinationPath
          HttpStatusCode  = 200
          FinalUri        = $null
          ResponseHeaders = "HTTP/1.1 200 OK`r`nLast-Modified: Wed, 15 Jul 2026 08:30:00 GMT`r`n"
        }
      }
      $Installer = [ordered]@{ Architecture = 'x64'; InstallerType = 'exe'; InstallerUrl = $Script:InstallerUrl }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ([ordered]@{}) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{}) -Logger $Script:Logger

      $Result.ReleaseDate | Should -Be '2026-07-15'
    }

    It 'Keeps an existing ReleaseDate instead of the Last-Modified header' {
      Mock Invoke-WinGetInstallerDownload -ModuleName WinGetManifestUpdate {
        [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1, 2, 3, 4))
        [pscustomobject]@{
          DestinationPath = $DestinationPath
          HttpStatusCode  = 200
          FinalUri        = $null
          ResponseHeaders = "HTTP/1.1 200 OK`r`nLast-Modified: Wed, 15 Jul 2026 08:30:00 GMT`r`n"
        }
      }
      $Installer = [ordered]@{ Architecture = 'x64'; InstallerType = 'exe'; InstallerUrl = $Script:InstallerUrl; ReleaseDate = '2020-01-01' }

      $Result = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller ([ordered]@{}) -InstallerEntry ([ordered]@{}) -InstallerFiles ([ordered]@{}) -Logger $Script:Logger

      $Result.ReleaseDate | Should -Be '2020-01-01'
    }
  }
}
