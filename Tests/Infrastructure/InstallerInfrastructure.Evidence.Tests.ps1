. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallerInfrastructureTestSetup.ps1')

Describe 'Get-InstallerRegistryAssociationInfo' {
  It 'reads literal protocol, ProgID, and OpenWithProgids evidence' {
    $Writes = @(
      [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Classes\example'; Name = $null; Value = 'Example protocol'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Classes\example'; Name = 'URL Protocol'; Value = ''; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Classes\example\shell\open\command'; Name = $null; Value = '"<InstallLocation>\Example.exe" "%1"'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\.example'; Name = $null; Value = 'Example.Document'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\.example\OpenWithProgids'; Name = 'Example.AlternateDocument'; Value = ''; Type = 'REG_NONE' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\Example.Document'; Name = $null; Value = 'Example document'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\Example.Document\shell\open\command'; Name = $null; Value = '"<InstallLocation>\Example.exe" "%1"'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Example'; Name = 'URL Protocol'; Value = ''; Type = 'REG_SZ' }
    )

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example')
    $Info.ProtocolAssociations[0].Command | Should -Be '"<InstallLocation>\Example.exe" "%1"'
    $Info.FileExtensionAssociations[0].ProgIds | Should -Be @('Example.Document', 'Example.AlternateDocument')
    $Info.FileExtensionAssociations[0].Command | Should -Be '"<InstallLocation>\Example.exe" "%1"'
  }

  It 'requires URL Protocol evidence and ignores dynamic class keys' {
    $Writes = @(
      [pscustomobject]@{ Root = 'HKCR'; Key = 'not-a-protocol'; Name = $null; Value = 'Not a protocol'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\{code:Protocol}'; Name = 'URL Protocol'; Value = ''; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 0; Key = '.sample'; Name = $null; Value = 'Sample.Document'; Type = 'REG_SZ' }
    )

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Info.Protocols | Should -BeNullOrEmpty
    $Info.FileExtensions | Should -Be @('sample')
    $Info.Diagnostics.Message | Should -Contain "Ignored non-literal protocol key '{code:Protocol}'."
  }

  It 'accepts a direct extension shell command without a ProgID' {
    $Writes = @(
      [pscustomobject]@{ Root = 'HKCR'; Key = '.wxproj'; Name = $null; Value = ''; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCR'; Key = '.wxproj\DefaultIcon'; Name = $null; Value = '<InstallLocation>\DevTools.exe'; Type = 'REG_SZ' },
      [pscustomobject]@{ Root = 'HKCR'; Key = '.wxproj\shell\Open\command'; Name = $null; Value = '"<InstallLocation>\DevTools.exe" "%1"'; Type = 'REG_SZ' }
    )

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Info.FileExtensions | Should -Be @('wxproj')
    $Info.FileExtensionAssociations[0].ProgIds | Should -BeNullOrEmpty
    $Info.FileExtensionAssociations[0].Command | Should -Be '"<InstallLocation>\DevTools.exe" "%1"'
    $Info.FileExtensionAssociations[0].DefaultIcon | Should -Be '<InstallLocation>\DevTools.exe'
    $Info.Diagnostics | Should -BeNullOrEmpty
  }

  It 'warns when an extension has neither a ProgID nor a direct command' {
    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite @(
      [pscustomobject]@{ Root = 'HKCR'; Key = '.incomplete'; Name = $null; Value = ''; Type = 'REG_SZ' }
    )

    $Info.Diagnostics.Message | Should -Contain "File extension '.incomplete' has neither a literal ProgID nor a direct open command."
  }
}
