BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\WinGetInstallerAnalyzer'
  $ProgressPreference = 'SilentlyContinue'

  function Get-WiseChromiumFixture {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$Url
    )
    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }
}

Describe 'Chromium updater tag parser' {
  It 'Should parse a certificate tag with big-endian length and URL-encoded values' {
    $RawTag = 'appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&appname=Google%20Chrome&needsadmin=prefers&brand=GTPM'
    $TagBytes = [Text.Encoding]::UTF8.GetBytes($RawTag)
    $Bytes = [Text.Encoding]::ASCII.GetBytes('certificate-prefixGact2.0Omaha') + [byte[]]([byte]($TagBytes.Length -shr 8), [byte]$TagBytes.Length) + $TagBytes

    $Info = ConvertFrom-ChromiumUpdaterTagData -Bytes $Bytes

    $Info.MarkerFound | Should -BeTrue
    $Info.IsTagged | Should -BeTrue
    $Info.ApplicationId | Should -Be '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
    $Info.ApplicationName | Should -Be 'Google Chrome'
    $Info.NeedsAdmin | Should -Be 'prefers'
    $Info.Brand | Should -Be 'GTPM'
  }

  It 'Should distinguish an untagged updater marker from a tagged application bootstrapper' {
    $Bytes = [Text.Encoding]::ASCII.GetBytes('Gact2.0Omaha') + [byte[]](0, 0)
    $Info = ConvertFrom-ChromiumUpdaterTagData -Bytes $Bytes

    $Info.MarkerFound | Should -BeTrue
    $Info.IsTagged | Should -BeFalse
    $Info.Length | Should -Be 0
  }

  It 'Should parse the UTF-16 Microsoft Edge certificate tag' {
    $RawTag = 'appguid={F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}&appname=Microsoft%20Edge%20WebView2%20Runtime&needsadmin=Prefers'
    $Bytes = [Text.Encoding]::Unicode.GetBytes("MSEDGE_${RawTag}_EGDESM")

    $Info = ConvertFrom-ChromiumUpdaterTagData -Bytes $Bytes

    $Info.MarkerFound | Should -BeTrue
    $Info.IsTagged | Should -BeTrue
    $Info.TagFormat | Should -BeExactly 'MicrosoftEdgeCertificateTag'
    $Info.ApplicationId | Should -BeExactly '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $Info.ApplicationName | Should -BeExactly 'Microsoft Edge WebView2 Runtime'
    $Info.NeedsAdmin | Should -BeExactly 'Prefers'
  }

  It 'Should parse the source-defined wide updater tag framing' {
    $RawTag = 'appguid={WIDE-APP}&appname=Wide%20Browser&needsadmin=false'
    $Bytes = [Text.Encoding]::Unicode.GetBytes("Gact2.0Omaha${RawTag}ahamO0.2tcaG")

    $Info = ConvertFrom-ChromiumUpdaterTagData -Bytes $Bytes

    $Info.TagFormat | Should -BeExactly 'ChromiumWideCertificateTag'
    $Info.ApplicationId | Should -BeExactly '{WIDE-APP}'
    $Info.ApplicationName | Should -BeExactly 'Wide Browser'
    $Info.NeedsAdmin | Should -BeExactly 'false'
  }
}

Describe 'Chromium resource classification' {
  BeforeEach {
    $Script:SyntheticPath = Join-Path $Script:FixtureDirectory 'synthetic-chromium.exe'
    [IO.File]::WriteAllBytes($Script:SyntheticPath, [byte[]](0x4D, 0x5A))
  }

  It 'Should identify the bare mini-installer from chrome and setup resources' {
    InModuleScope ChromiumSetup -Parameters @{ SyntheticPath = $Script:SyntheticPath } {
      param($SyntheticPath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 0; Size = 0 } } } }
      Mock Get-PEResourceInfo {
        @(
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'B7'; TypeId = $null; Name = 'chrome.packed.7z'; Id = $null; Offset = 100; Size = 200 }
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'BL'; TypeId = $null; Name = 'setup.ex_'; Id = $null; Offset = 300; Size = 400 }
        )
      }
      Mock Read-ChromiumInstallerTagFromStream { [pscustomobject]@{ MarkerFound = $false; IsTagged = $false; ApplicationId = $null; ApplicationName = $null; NeedsAdmin = $null } }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath
      $Info.Variant | Should -Be 'ChromiumMiniInstaller'
      $Info.Scope | Should -Be 'user'
      $Info.SupportedScopes | Should -Be @('user', 'machine')
      $Info.MachineScopeSwitch | Should -Be '--system-level'
      $Info.ExecutedPayloads | Should -Be @('setup.exe')
      Should -Invoke Get-PELayout -Times 1 -Exactly
      Should -Invoke Get-PEResourceInfo -Times 1 -Exactly
    }
  }

  It 'Should identify a branded mini-installer archive from the resource pairing' {
    InModuleScope ChromiumSetup -Parameters @{ SyntheticPath = $Script:SyntheticPath } {
      param($SyntheticPath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 0; Size = 0 } } } }
      Mock Get-PEResourceInfo {
        @(
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'B7'; TypeId = $null; Name = 'VIVALDI.PACKED.7Z'; Id = $null; Offset = 100; Size = 200 }
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'BL'; TypeId = $null; Name = 'SETUP.EX_'; Id = $null; Offset = 300; Size = 400 }
        )
      }
      Mock Read-ChromiumInstallerTagFromStream { [pscustomobject]@{ MarkerFound = $false; IsTagged = $false; ApplicationId = $null; ApplicationName = $null; NeedsAdmin = $null } }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath
      $Info.Variant | Should -Be 'ChromiumMiniInstaller'
      $Info.ArchiveResourceName | Should -Be 'VIVALDI.PACKED.7Z'
      $Info.SetupResourceName | Should -Be 'SETUP.EX_'
      $Info.NestedFiles | Should -Be @('setup.exe', 'vivaldi.7z')
    }
  }

  It 'Should identify Chromium Updater from its B7 updater resource' {
    InModuleScope ChromiumSetup -Parameters @{ SyntheticPath = $Script:SyntheticPath } {
      param($SyntheticPath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 0; Size = 0 } } } }
      Mock Get-PEResourceInfo { [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'B7'; TypeId = $null; Name = 'updater.packed.7z'; Id = $null; Offset = 100; Size = 200 } }
      Mock Read-ChromiumInstallerTagFromStream { [pscustomobject]@{ MarkerFound = $true; IsTagged = $false; ApplicationId = $null; ApplicationName = $null; NeedsAdmin = $null } }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath
      $Info.Variant | Should -Be 'ChromiumUpdater'
      $Info.ExecutedPayloads | Should -Be @('bin\updater.exe')
      $Info.MachineScopeSwitch | Should -Be '--system'
    }
  }

  It 'Should identify Omaha and treat appguid as non-ARP identity' {
    InModuleScope ChromiumSetup -Parameters @{ SyntheticPath = $Script:SyntheticPath } {
      param($SyntheticPath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 1; Size = 1 } } } }
      Mock Get-PEResourceInfo { [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'B'; TypeId = $null; Name = $null; Id = 102; Offset = 100; Size = 200 } }
      Mock Read-ChromiumInstallerTagFromStream { [pscustomobject]@{ MarkerFound = $true; IsTagged = $true; ApplicationId = '{APP-ID}'; ApplicationName = 'Example Browser'; NeedsAdmin = 'true' } }
      Mock Get-ChromiumOmahaOfflineManifestInfo { $null }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath
      $Info.Variant | Should -Be 'Omaha'
      $Info.DisplayName | Should -Be 'Example Browser'
      $Info.ApplicationId | Should -Be '{APP-ID}'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.Scope | Should -Be 'machine'
      $Info.Warnings[0] | Should -BeLike '*not an ARP ProductCode*'
    }
  }

  It 'Should leave online status unknown when an Omaha offline-manifest check fails' {
    InModuleScope ChromiumSetup -Parameters @{ SyntheticPath = $Script:SyntheticPath } {
      param($SyntheticPath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 1; Size = 1 } } } }
      Mock Get-PEResourceInfo { [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'B'; Id = 102; Offset = 100; Size = 200 } }
      Mock Read-ChromiumInstallerTagFromStream { [pscustomobject]@{ MarkerFound = $true; IsTagged = $true; ApplicationId = '{APP-ID}'; ApplicationName = 'Example Browser'; NeedsAdmin = 'true' } }
      Mock Get-ChromiumOmahaOfflineManifestInfo { throw 'malformed payload' }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath

      $Info.OfflineManifestChecked | Should -BeTrue
      $Info.IsOnlineBootstrapper | Should -BeNullOrEmpty
      ($Info.Warnings -join ' ') | Should -BeLike '*could not be checked*malformed payload*'
    }
  }

  It 'Should prefer B7 setup resources over BL and BN like Chromium mini_installer' {
    InModuleScope ChromiumSetup -Parameters @{ SyntheticPath = $Script:SyntheticPath } {
      param($SyntheticPath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 0; Size = 0 } } } }
      Mock Get-PEResourceInfo {
        @(
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'BN'; Name = 'CHROME.7Z'; Offset = 100; Size = 200 }
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'BN'; Name = 'SETUP.EXE'; Offset = 300; Size = 400 }
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'BL'; Name = 'SETUP.EX_'; Offset = 500; Size = 600 }
          [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'B7'; Name = 'SETUP.PACKED.7Z'; Offset = 700; Size = 800 }
        )
      }
      Mock Read-ChromiumInstallerTagFromStream { [pscustomobject]@{ MarkerFound = $false; IsTagged = $false; ApplicationId = $null; ApplicationName = $null; NeedsAdmin = $null } }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath

      $Info.Variant | Should -BeExactly 'ChromiumMiniInstaller'
      $Info.SetupResourceName | Should -BeExactly 'SETUP.PACKED.7Z'
    }
  }

  It 'Should resolve Brave updater identities to source-defined uninstall keys' -ForEach @(
    @{ ApplicationId = '{AFE6A462-C574-4B8A-AF43-4CC60DF4563B}'; ProductCode = 'BraveSoftware Brave-Browser' }
    @{ ApplicationId = '{103BD053-949B-43A8-9120-2E424887DE11}'; ProductCode = 'BraveSoftware Brave-Browser-Beta' }
    @{ ApplicationId = '{CB2150F2-595F-4633-891A-E39720CE0531}'; ProductCode = 'BraveSoftware Brave-Browser-Dev' }
    @{ ApplicationId = '{C6CB981E-DB30-4876-8639-109F8933582C}'; ProductCode = 'BraveSoftware Brave-Browser-Nightly' }
    @{ ApplicationId = '{F1EF32DE-F987-4289-81D2-6C4780027F9B}'; ProductCode = 'BraveSoftware Brave-Origin' }
    @{ ApplicationId = '{56DA94FD-D872-416B-BFC4-1D7011DA7473}'; ProductCode = 'BraveSoftware Brave-Origin-Beta' }
    @{ ApplicationId = '{716D6A4A-D071-47A8-AC64-DBDE3EE3797B}'; ProductCode = 'BraveSoftware Brave-Origin-Dev' }
    @{ ApplicationId = '{50474E96-9CD2-4BC8-B0A7-0D4B6EF2E709}'; ProductCode = 'BraveSoftware Brave-Origin-Nightly' }
  ) {
    InModuleScope ChromiumSetup -Parameters @{ ApplicationId = $ApplicationId; ProductCode = $ProductCode } {
      param($ApplicationId, $ProductCode)
      Resolve-BraveChromiumProductCode -ApplicationId $ApplicationId.ToLowerInvariant() -Publisher 'BraveSoftware Inc.' | Should -BeExactly $ProductCode
    }
  }

  It 'Should resolve the documented WebView2 client identity to its uninstall key' {
    InModuleScope ChromiumSetup {
      Resolve-MicrosoftEdgeChromiumProductCode -ApplicationId '{f3017226-fe2a-4295-8bdf-00c3a9a7e4c5}' -Publisher 'Microsoft Corporation' | Should -BeExactly 'Microsoft EdgeWebView'
      Resolve-MicrosoftEdgeChromiumProductCode -ApplicationId '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -Publisher 'Example Publisher' | Should -BeNullOrEmpty
    }
  }

  It 'Should resolve Google Chrome ARP keys from channel switches' {
    $Info = [pscustomobject]@{
      Variant     = 'ChromiumMiniInstaller'
      Publisher   = 'Google LLC'
      ProductName = 'Google Chrome Installer'
    }

    Resolve-ChromiumSetupProductCode -Info $Info -InstallerSwitches ([ordered]@{ Custom = '--chrome-sxs --do-not-launch-chrome' }) | Should -Be 'Google Chrome SxS'
    Resolve-ChromiumSetupProductCode -Info $Info -InstallerSwitches ([ordered]@{ Custom = '--do-not-launch-chrome --chrome-beta' }) | Should -Be 'Google Chrome Beta'
    Resolve-ChromiumSetupProductCode -Info $Info -InstallerSwitches ([ordered]@{ Custom = '--chrome-dev --do-not-launch-chrome' }) | Should -Be 'Google Chrome Dev'
    Resolve-ChromiumSetupProductCode -Info $Info -InstallerSwitches ([ordered]@{ Custom = '--do-not-launch-chrome' }) | Should -Be 'Google Chrome'
  }

  It 'Should not infer a ProductCode for non-Google Chromium installers' {
    $Info = [pscustomobject]@{
      Variant     = 'ChromiumMiniInstaller'
      Publisher   = 'Example Publisher'
      ProductName = 'Example Browser Installer'
    }

    Resolve-ChromiumSetupProductCode -Info $Info -InstallerSwitches ([ordered]@{ Custom = '--chrome-sxs' }) | Should -BeNullOrEmpty
  }

  It 'Should resolve the Vivaldi ARP key from exact mini-installer branding' {
    $Info = [pscustomobject]@{
      Variant             = 'ChromiumMiniInstaller'
      Publisher           = 'Vivaldi Technologies AS'
      ProductName         = 'Vivaldi Installer'
      ArchiveResourceName = 'VIVALDI.PACKED.7Z'
    }

    Resolve-ChromiumSetupProductCode -Info $Info -InstallerSwitches ([ordered]@{ Custom = '--do-not-launch-chrome' }) | Should -Be 'Vivaldi'

    $WrappedInfo = [pscustomobject]@{ Variant = $Info.Variant; Metadata = $Info }
    Resolve-ChromiumSetupProductCode -Info $WrappedInfo -InstallerSwitches ([ordered]@{ Custom = '--do-not-launch-chrome' }) | Should -Be 'Vivaldi'
  }
}

Describe 'Wise MSI wrapper parser' {
  It 'Should parse TI Connect through its validated embedded MSI' {
    $Installer = Get-WiseChromiumFixture -Name 'TI-Connect-4.0.0.218.exe' -Url 'https://education.ti.com/download/en/ed-tech/14D11109C9F44D55B9BBF65E5A62E7F1/A885DD53BEC14496971FE5A42F1014CF/TI-Connect-4.0.0.218.exe'
    $Info = Get-WiseInfo -Path $Installer

    $Info.InstallerType | Should -Be 'Wise MSI'
    $Info.DisplayVersion | Should -Be '4.0.0.218'
    $Info.Publisher | Should -Be 'Texas Instruments Inc.'
    $Info.ProductCode | Should -Be '{D06BA64C-4447-49B4-B99D-E85BEA9E1035}'
    $Info.UpgradeCode | Should -Be '{FCEEDA79-4099-4C10-B717-F72EF53CCDA9}'
    $Info.Scope | Should -Be 'machine'
    $Info.NestedInstallerBuilder | Should -Be 'InstallShield'
    $Info.InstallLocationProperty | Should -Be 'INSTALLDIR'
    $Info.AppsAndFeaturesInstallerType | Should -Be 'msi'
    $Info.FileExtensions | Should -Contain '8xp'
    Test-WiseInstaller -Path $Installer | Should -BeTrue
  }
}

Describe 'Chromium real installer fixtures' {
  It 'Should identify and expand legacy Google Updater <Version> as Omaha' -ForEach @(
    @{
      Version = '1.3.35.452'
      Name    = 'GoogleUpdateSetup-1.3.35.452.exe'
      Url     = 'https://dl.google.com/release2/update2/AOVe98a3fi3oIA5CfTl3ibc_1.3.35.452/GoogleUpdateSetup.exe'
    }
    @{
      Version = '1.3.36.372'
      Name    = 'GoogleUpdateSetup-1.3.36.372.exe'
      Url     = 'https://dl.google.com/release2/update2/iqmnfy5ub2wrt6itb67uu4wcci_1.3.36.372/GoogleUpdateSetup.exe'
    }
  ) {
    $Installer = Get-WiseChromiumFixture -Name $Name -Url $Url
    $Info = Get-ChromiumSetupInfo -Path $Installer
    $Destination = Join-Path $Script:FixtureDirectory "GoogleUpdateSetup-$Version-expanded"
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    $Files = @(Expand-ChromiumSetupInstaller -Path $Installer -DestinationPath $Destination -Name '*.exe')

    $Info.Variant | Should -Be 'Omaha'
    $Info.OuterProductVersion | Should -Be $Version
    $Info.IsOnlineBootstrapper | Should -BeFalse
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.UserScopeSwitch | Should -Be '/install "runtime=true" /enterprise'
    $Info.MachineScopeSwitch | Should -Be '/install "runtime=true&needsadmin=true" /enterprise'
    $Info.Resources | Where-Object { $_.Type -eq 'B' -and $_.Id -eq 102 } | Should -HaveCount 1
    $Files[0].Name | Should -Be 'GoogleUpdate.exe'
    Test-OmahaInstaller -Path $Installer | Should -BeTrue
  }

  It 'Should identify the standalone Google Updater package without treating it as a tagged app installer' {
    $Installer = Get-WiseChromiumFixture -Name 'GoogleUpdaterSetup-151.0.7910.0.exe' -Url 'https://dl.google.com/release2/update2/njqmbtxpvtav47blpyd6xsgcju_151.0.7910.0/UpdaterSetup.exe'
    $Info = Get-ChromiumSetupInfo -Path $Installer
    $Destination = Join-Path $Script:FixtureDirectory 'GoogleUpdater-Expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    $Files = @(Expand-ChromiumSetupInstaller -Path $Installer -DestinationPath $Destination -Name 'bin\updater.exe')

    $Info.Variant | Should -Be 'ChromiumUpdater'
    $Info.IsOnlineBootstrapper | Should -BeFalse
    $Info.ExecutedPayloads | Should -Contain 'bin\updater.exe'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Files | Should -HaveCount 1
    $Files[0].Name | Should -Be 'updater.exe'
  }

  It 'Should classify current online bootstrapper <Package>' -ForEach @(
    @{
      Package       = 'Google.Chrome'
      Name          = 'ChromeOnlineSetup.exe'
      Url           = 'https://dl.google.com/chrome/install/latest/chrome_installer.exe'
      Variant       = 'ChromiumUpdater'
      ApplicationId = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
      ProductCode   = $null
    }
    @{
      Package       = 'Brave.Brave.Beta'
      Name          = 'BraveBrowserBetaSetup-1.93.120.exe'
      Url           = 'https://github.com/brave/brave-browser/releases/download/v1.93.120/BraveBrowserBetaSetup.exe'
      Variant       = 'Omaha'
      ApplicationId = '{103BD053-949B-43A8-9120-2E424887DE11}'
      ProductCode   = 'BraveSoftware Brave-Browser-Beta'
    }
    @{
      Package       = 'Brave Origin Beta installer'
      Name          = 'BraveOriginBetaSetup-1.93.120.exe'
      Url           = 'https://github.com/brave/brave-browser/releases/download/v1.93.120/BraveOriginBetaSetup.exe'
      Variant       = 'Omaha'
      ApplicationId = '{56DA94FD-D872-416B-BFC4-1D7011DA7473}'
      ProductCode   = 'BraveSoftware Brave-Origin-Beta'
    }
    @{
      Package       = 'Microsoft.EdgeWebView2Runtime'
      Name          = 'MicrosoftEdgeWebView2Bootstrapper.exe'
      Url           = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703'
      Variant       = 'Omaha'
      ApplicationId = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
      ProductCode   = 'Microsoft EdgeWebView'
    }
  ) {
    $Installer = Get-WiseChromiumFixture -Name $Name -Url $Url
    $Info = Get-ChromiumSetupInfo -Path $Installer

    $Info.Variant | Should -BeExactly $Variant
    $Info.ApplicationId | Should -BeExactly $ApplicationId
    $Info.ProductCode | Should -BeExactly $ProductCode
    $Info.IsOnlineBootstrapper | Should -BeTrue
  }

  It 'Should validate cached bare mini-installer resources without requiring the large CI download' {
    $Installer = Join-Path $Script:FixtureDirectory 'ChromeMiniInstallerUncompressed-150.0.7871.47-x64.exe'
    if (-not (Test-Path -LiteralPath $Installer)) { Set-ItResult -Skipped -Because 'The 489 MB Chrome mini-installer fixture is not cached.'; return }
    $Info = Get-ChromiumSetupInfo -Path $Installer

    $Info.Variant | Should -Be 'ChromiumMiniInstaller'
    $Info.Resources.Name | Should -Contain 'CHROME.7Z'
    $Info.Resources.Name | Should -Contain 'SETUP.EXE'
  }

  It 'Should parse and expand a cached Vivaldi branded mini-installer' {
    $Installer = Join-Path $Script:FixtureDirectory 'Vivaldi.8.2.4106.4.x64.exe'
    if (-not (Test-Path -LiteralPath $Installer)) { Set-ItResult -Skipped -Because 'The Vivaldi Snapshot fixture is not cached.'; return }
    $Destination = Join-Path $Script:FixtureDirectory 'Vivaldi-Expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue

    $Info = Get-ChromiumSetupInfo -Path $Installer
    $Files = @(Expand-ChromiumSetupInstaller -Path $Installer -DestinationPath $Destination -Name 'setup.exe')

    $Info.Variant | Should -Be 'ChromiumMiniInstaller'
    $Info.ArchiveResourceName | Should -Be 'VIVALDI.PACKED.7Z'
    $Info.NestedFiles | Should -Contain 'vivaldi.7z'
    $Files | Should -HaveCount 1
    $Files[0].Name | Should -Be 'setup.exe'
    [Diagnostics.FileVersionInfo]::GetVersionInfo($Files[0].FullName).ProductVersion | Should -Be '8.2.4106.4'
  }

  It 'Should expand a cached Omaha fixture through LZMA, BCJ2, and TAR' {
    $Installer = Join-Path $Script:FixtureDirectory 'BraveBrowserStandaloneSetup-1.92.139.exe'
    if (-not (Test-Path -LiteralPath $Installer)) { Set-ItResult -Skipped -Because 'The 153 MB Brave Omaha fixture is not cached.'; return }
    $Info = Get-ChromiumSetupInfo -Path $Installer
    $Destination = Join-Path $Script:FixtureDirectory 'Brave-Omaha-Expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    $Files = @(Expand-ChromiumSetupInstaller -Path $Installer -DestinationPath $Destination -Name '*.exe' -MaximumExpandedBytes 1073741824)

    $Files[0].Name | Should -Be 'BraveUpdate.exe'
    $Files.Name | Should -Contain 'BraveUpdateCore.exe'
    $Info.Variant | Should -Be 'Omaha'
    $Info.ProductCode | Should -BeExactly 'BraveSoftware Brave-Browser'
    $Info.DisplayVersion | Should -BeExactly '150.1.92.139'
    $Info.IsOnlineBootstrapper | Should -BeFalse
    $Info.OfflineManifest.Packages[0].Name | Should -BeExactly 'brave_installer.exe'
    $Info.OfflineManifest.InstallAction.Arguments | Should -BeExactly '--do-not-launch-chrome'
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should parse a cached Microsoft Edge WebView2 standalone installer' {
    $Installer = Join-Path $Script:FixtureDirectory 'MicrosoftEdgeWebView2RuntimeInstallerX64-150.0.4078.65.exe'
    if (-not (Test-Path -LiteralPath $Installer)) { Set-ItResult -Skipped -Because 'The 204 MB Edge WebView2 fixture is not cached.'; return }

    $Info = Get-ChromiumSetupInfo -Path $Installer

    $Info.Variant | Should -BeExactly 'Omaha'
    $Info.UpdaterTag.TagFormat | Should -BeExactly 'MicrosoftEdgeCertificateTag'
    $Info.ApplicationId | Should -BeExactly '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $Info.DisplayName | Should -BeExactly 'Microsoft Edge WebView2 Runtime'
    $Info.DisplayVersion | Should -BeExactly '150.0.4078.65'
    $Info.ProductCode | Should -BeExactly 'Microsoft EdgeWebView'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.IsOnlineBootstrapper | Should -BeFalse
    $Info.OfflineManifest.InstallAction.Arguments | Should -BeExactly '--msedgewebview --verbose-logging --do-not-launch-msedge'
    $Info.Warnings | Should -BeNullOrEmpty
  }
}

Describe 'WinGet analyzer Wise and Chromium routing' {
  It 'Should prefer the Wise parser over generic EXE heuristics' {
    $Installer = Get-WiseChromiumFixture -Name 'TI-Connect-4.0.0.218.exe' -Url 'https://education.ti.com/download/en/ed-tech/14D11109C9F44D55B9BBF65E5A62E7F1/A885DD53BEC14496971FE5A42F1014CF/TI-Connect-4.0.0.218.exe'
    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'Wise' -and $_.Success } | Select-Object -First 1

    $Result.Result.Family | Should -Be 'Wise'
    $Result.Result.ProductCode | Should -Be '{D06BA64C-4447-49B4-B99D-E85BEA9E1035}'
    $Result.Result.SuggestedManifestFields.InstallerSwitches.InstallLocation | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
  }

  It 'Should emit Chromium Updater-specific switch and scope evidence' {
    $Installer = Get-WiseChromiumFixture -Name 'GoogleUpdaterSetup-151.0.7910.0.exe' -Url 'https://dl.google.com/release2/update2/njqmbtxpvtav47blpyd6xsgcju_151.0.7910.0/UpdaterSetup.exe'
    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'Chromium Setup' -and $_.Success } | Select-Object -First 1

    $Result.Result.Variant | Should -Be 'ChromiumUpdater'
    $Result.Result.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '--install --silent'
    $Result.Result.SuggestedManifestFields.ScopeSwitches.Machine | Should -Be '--system --enterprise'
  }

  It 'Should emit Omaha-specific switches for the legacy Google Updater package' {
    $Installer = Get-WiseChromiumFixture -Name 'GoogleUpdateSetup-1.3.36.372.exe' -Url 'https://dl.google.com/release2/update2/iqmnfy5ub2wrt6itb67uu4wcci_1.3.36.372/GoogleUpdateSetup.exe'
    $Analysis = Get-WinGetInstallerAnalysis -Path $Installer
    $Result = $Analysis.ParserResults | Where-Object { $_.Name -eq 'Chromium Setup' -and $_.Success } | Select-Object -First 1

    $Result.Result.Variant | Should -Be 'Omaha'
    $Result.Result.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/silent'
    $Result.Result.SuggestedManifestFields.ScopeSwitches.User | Should -Be '/install "runtime=true" /enterprise'
    $Result.Result.SuggestedManifestFields.ScopeSwitches.Machine | Should -Be '/install "runtime=true&needsadmin=true" /enterprise'
  }
}
