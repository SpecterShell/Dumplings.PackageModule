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
      Mock Read-ChromiumInstallerTag { [pscustomobject]@{ MarkerFound = $false; IsTagged = $false; ApplicationId = $null; ApplicationName = $null; NeedsAdmin = $null } }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath
      $Info.Variant | Should -Be 'ChromiumMiniInstaller'
      $Info.Scope | Should -Be 'user'
      $Info.SupportedScopes | Should -Be @('user', 'machine')
      $Info.MachineScopeSwitch | Should -Be '--system-level'
      $Info.ExecutedPayloads | Should -Be @('setup.exe')
    }
  }

  It 'Should identify Chromium Updater from its B7 updater resource' {
    InModuleScope ChromiumSetup -Parameters @{ SyntheticPath = $Script:SyntheticPath } {
      param($SyntheticPath)
      Mock Get-PELayout { [pscustomobject]@{ DataDirectories = @{ Certificate = [pscustomobject]@{ Rva = 0; Size = 0 } } } }
      Mock Get-PEResourceInfo { [pscustomobject]@{ Path = $SyntheticPath; TypeName = 'B7'; TypeId = $null; Name = 'updater.packed.7z'; Id = $null; Offset = 100; Size = 200 } }
      Mock Read-ChromiumInstallerTag { [pscustomobject]@{ MarkerFound = $true; IsTagged = $false; ApplicationId = $null; ApplicationName = $null; NeedsAdmin = $null } }

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
      Mock Read-ChromiumInstallerTag { [pscustomobject]@{ MarkerFound = $true; IsTagged = $true; ApplicationId = '{APP-ID}'; ApplicationName = 'Example Browser'; NeedsAdmin = 'true' } }

      $Info = Get-ChromiumSetupInfo -Path $SyntheticPath
      $Info.Variant | Should -Be 'Omaha'
      $Info.DisplayName | Should -Be 'Example Browser'
      $Info.ApplicationId | Should -Be '{APP-ID}'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.Scope | Should -Be 'machine'
      $Info.Warnings[0] | Should -BeLike '*not an ARP ProductCode*'
    }
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

  It 'Should validate cached bare mini-installer resources without requiring the large CI download' {
    $Installer = Join-Path $Script:FixtureDirectory 'ChromeMiniInstallerUncompressed-150.0.7871.47-x64.exe'
    if (-not (Test-Path -LiteralPath $Installer)) { Set-ItResult -Skipped -Because 'The 489 MB Chrome mini-installer fixture is not cached.'; return }
    $Info = Get-ChromiumSetupInfo -Path $Installer

    $Info.Variant | Should -Be 'ChromiumMiniInstaller'
    $Info.Resources.Name | Should -Contain 'CHROME.7Z'
    $Info.Resources.Name | Should -Contain 'SETUP.EXE'
  }

  It 'Should expand a cached Omaha fixture through LZMA, BCJ2, and TAR' {
    $Installer = Join-Path $Script:FixtureDirectory 'BraveBrowserStandaloneSetup-1.92.139.exe'
    if (-not (Test-Path -LiteralPath $Installer)) { Set-ItResult -Skipped -Because 'The 153 MB Brave Omaha fixture is not cached.'; return }
    $Destination = Join-Path $Script:FixtureDirectory 'Brave-Omaha-Expanded'
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
    $Files = @(Expand-ChromiumSetupInstaller -Path $Installer -DestinationPath $Destination -Name '*.exe' -MaximumExpandedBytes 1073741824)

    $Files[0].Name | Should -Be 'BraveUpdate.exe'
    $Files.Name | Should -Contain 'BraveUpdateCore.exe'
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
