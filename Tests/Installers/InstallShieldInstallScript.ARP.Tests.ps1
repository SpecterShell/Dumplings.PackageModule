. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldInstallScriptTestSetup.ps1')

Describe 'InstallScript ARP and associations' -Tag Unit {
  It 'reconstructs documented MaintenanceStart ARP defaults without using response metadata as version evidence' {
    $Path = Join-Path $TestDrive 'setup.inx'
    $ResponsePath = Join-Path $TestDrive 'setup.iss'
    New-TestInstallScriptFile -Path $Path -String @(
      'program', 'OnMoveData', 'MaintenanceStart', 'ProductGuid', 'DisplayName', 'DisplayVersion', 'Publisher',
      'Software\Microsoft\Windows\CurrentVersion\Uninstall\'
    )
    @'
[InstallShield Silent]
Version=v7.00
File=Response File
[Application]
Name=Stale response name
Version=0.0.1
Company=Stale response publisher
'@ | Set-Content -LiteralPath $ResponsePath
    $Installer = [pscustomobject]@{
      HasInstallScript   = $true
      InxFiles           = @($Path)
      SetupConfiguration = [ordered]@{
        Startup = [ordered]@{
          Product     = 'Contoso Editor'
          ProductGUID = '11111111-2222-3333-4444-555555555555'
          CompanyName = 'Contoso, Ltd.'
        }
      }
    }

    $Info = Get-InstallShieldInstallScriptInfo -Installer $Installer

    $Info.ProductCode | Should -Be '{11111111-2222-3333-4444-555555555555}'
    $Info.ProjectProductCode | Should -Be $Info.ProductCode
    $Info.CompiledScriptPath | Should -Be $Path
    $Info.DisplayName | Should -Be 'Contoso Editor'
    $Info.Publisher | Should -Be 'Contoso, Ltd.'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesProductCode | Should -Be $Info.ProductCode
    $Info.AppsAndFeaturesInstallerType | Should -Be 'exe'
    $Info.AppsAndFeaturesEntries[0].DisplayName | Should -Be 'Contoso Editor'
    $Info.RegistryWrites.Name | Should -Contain 'ProductGuid'
    $Info.RegistryWrites.Name | Should -Contain 'DisplayName'
    $Info.RegistryWrites.Name | Should -Contain 'Publisher'
    $Info.UnresolvedFields | Should -Contain 'DisplayVersion'
    $Info.UnresolvedFields | Should -Contain 'Scope'
    $Info.UnresolvedFields | Should -Contain 'DefaultInstallLocation'
  }

  It 'applies complete RegDBSetItem overrides and excludes hidden built-in uninstall entries' {
    $Installer = [pscustomobject]@{
      SetupConfiguration = [ordered]@{
        Startup = [ordered]@{
          Product     = 'Project default'
          ProductGUID = '11111111-2222-3333-4444-555555555555'
          CompanyName = 'Project publisher'
        }
      }
    }
    $BaseAnalysis = [ordered]@{
      ArpRuntimeEvidence = @('MaintenanceStart', 'Software\Microsoft\Windows\CurrentVersion\Uninstall\')
      RegistryWrites     = @()
      RegistryItems      = @(
        [pscustomobject]@{ Complete = $true; Name = 'DisplayName'; Data = 'Configured product' }
        [pscustomobject]@{ Complete = $true; Name = 'DisplayVersion'; Data = '2.5.1' }
        [pscustomobject]@{ Complete = $true; Name = 'Publisher'; Data = 'Configured publisher' }
        [pscustomobject]@{ Complete = $true; Name = 'InstallLocation'; Data = 'C:\Program Files\Configured' }
        [pscustomobject]@{ Complete = $true; Name = 'UninstallString'; Data = 'C:\Program Files\Configured\uninstall.exe' }
        [pscustomobject]@{ Complete = $true; Name = 'DisplayIcon'; Data = 'C:\Program Files\Configured\app.exe,0' }
        [pscustomobject]@{ Complete = $true; Name = 'UrlInfoAbout'; Data = 'https://example.test/product' }
        [pscustomobject]@{ Complete = $true; Name = 'HelpLink'; Data = 'https://example.test/support' }
      )
    }

    $Visible = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis ([pscustomobject]$BaseAnalysis)

    $Visible.DisplayName | Should -Be 'Configured product'
    $Visible.DisplayVersion | Should -Be '2.5.1'
    $Visible.Publisher | Should -Be 'Configured publisher'
    $Visible.DefaultInstallLocation | Should -Be 'C:\Program Files\Configured'
    $Visible.UninstallString | Should -Be 'C:\Program Files\Configured\uninstall.exe'
    $Visible.DisplayIcon | Should -Be 'C:\Program Files\Configured\app.exe,0'
    $Visible.URLInfoAbout | Should -Be 'https://example.test/product'
    $Visible.HelpLink | Should -Be 'https://example.test/support'
    $Visible.WritesAppsAndFeaturesEntry | Should -BeTrue

    $BaseAnalysis.RegistryItems += [pscustomobject]@{ Complete = $true; Name = 'SystemComponent'; Data = '1' }
    $Hidden = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis ([pscustomobject]$BaseAnalysis)

    $Hidden.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Hidden.ProductCode | Should -BeNullOrEmpty
    $Hidden.UninstallString | Should -BeNullOrEmpty
    $Hidden.DisplayIcon | Should -BeNullOrEmpty
    $Hidden.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $Hidden.Diagnostics.Message -join ' ' | Should -Match 'SystemComponent=1'
  }

  It 'preserves registry-only metadata from an explicit visible uninstall entry' {
    $Installer = [pscustomobject]@{ SetupConfiguration = [ordered]@{} }
    $Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Contoso.Editor'
    $RegistryValues = [ordered]@{
      DisplayName          = 'Contoso Editor'
      DisplayVersion       = '3.2.1'
      Publisher            = 'Contoso'
      InstallLocation      = 'C:\Program Files\Contoso Editor'
      UninstallString      = 'C:\Program Files\Contoso Editor\uninstall.exe'
      QuietUninstallString = 'C:\Program Files\Contoso Editor\uninstall.exe /s'
      DisplayIcon          = 'C:\Program Files\Contoso Editor\editor.exe,0'
      URLInfoAbout         = 'https://example.test/editor'
      HelpLink             = 'https://example.test/editor/help'
    }
    $Writes = foreach ($Value in $RegistryValues.GetEnumerator()) {
      [pscustomobject]@{
        Complete = $true
        Root     = 'HKLM'
        Key      = $Key
        Name     = $Value.Key
        Type     = 'REG_SZ'
        Data     = $Value.Value
      }
    }
    $Analysis = [pscustomobject]@{
      ArpRuntimeEvidence = @()
      RegistryWrites     = @($Writes)
      RegistryItems      = @()
    }

    $Info = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis $Analysis

    $Info.ProductCode | Should -Be 'Contoso.Editor'
    $Info.Scope | Should -Be 'machine'
    $Info.UninstallString | Should -Be 'C:\Program Files\Contoso Editor\uninstall.exe'
    $Info.QuietUninstallString | Should -Be 'C:\Program Files\Contoso Editor\uninstall.exe /s'
    $Info.DisplayIcon | Should -Be 'C:\Program Files\Contoso Editor\editor.exe,0'
    $Info.URLInfoAbout | Should -Be 'https://example.test/editor'
    $Info.HelpLink | Should -Be 'https://example.test/editor/help'
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'UninstallString'
  }

  It 'keeps HKEY_USER_SELECTABLE uninstall entries while leaving scope unresolved' {
    $Analysis = [pscustomobject]@{
      ArpRuntimeEvidence = @()
      RegistryItems      = @()
      RegistryWrites     = @(
        [pscustomobject]@{ Complete = $true; Root = 'SHCTX'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Dumplings.App'; Name = 'DisplayName'; Type = 'REG_SZ'; Data = 'Dumplings App' }
      )
    }

    $Info = Get-InstallShieldInstallScriptArpInfo -Installer ([pscustomobject]@{ SetupConfiguration = [ordered]@{} }) -Analysis $Analysis

    $Info.ProductCode | Should -Be 'Dumplings.App'
    $Info.DisplayName | Should -Be 'Dumplings App'
    $Info.Scope | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'Scope'
  }

  It 'rejects malformed ProductGUID metadata instead of inventing an uninstall key' {
    $Path = Join-Path $TestDrive 'malformed-guid.inx'
    New-TestInstallScriptFile -Path $Path -String @('MaintenanceStart', 'Software\Microsoft\Windows\CurrentVersion\Uninstall\')
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path
    $Installer = [pscustomobject]@{
      SetupConfiguration = [ordered]@{ Startup = [ordered]@{ Product = 'Contoso'; ProductGUID = 'not-a-guid' } }
    }

    $ArpInfo = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis $Analysis

    $ArpInfo.ProductCode | Should -BeNullOrEmpty
    $ArpInfo.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $ArpInfo.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $ArpInfo.Diagnostics.Message | Should -Contain "Setup.ini ProductGUID 'not-a-guid' is not a valid GUID and is not used as ProductCode evidence."
  }

  It 'keeps project identity separate when compiled ARP registration evidence is absent' {
    $Path = Join-Path $TestDrive 'no-registration.inx'
    New-TestInstallScriptFile -Path $Path -String @('program', 'FeatureTransferData')
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $Path
    $Installer = [pscustomobject]@{
      SetupConfiguration = [ordered]@{
        Startup = [ordered]@{
          Product     = 'Contoso Portable Tool'
          ProductGUID = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
          CompanyName = 'Contoso'
        }
      }
    }

    $ArpInfo = Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis $Analysis

    $ArpInfo.ProjectProductCode | Should -Be '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
    $ArpInfo.ProjectName | Should -Be 'Contoso Portable Tool'
    $ArpInfo.ProductCode | Should -BeNullOrEmpty
    $ArpInfo.DisplayName | Should -BeNullOrEmpty
    $ArpInfo.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $ArpInfo.AppsAndFeaturesEntries | Should -BeNullOrEmpty
  }
}
