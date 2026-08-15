. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallerBridgeTestSetup.ps1')

Describe 'Bridge regressions' {
  It 'Should keep parser modules outside the shared Dumplings session autoload path' {
    Test-Path (Join-Path $Script:DumplingsModuleRoot '..' '..' 'Modules' 'InstallerParsers' 'Index.ps1') | Should -BeFalse
    Test-Path (Join-Path $Script:DumplingsModuleRoot '..' '..' 'Modules' 'InstallerParsers' 'GPL3') | Should -BeFalse
    Test-Path (Join-Path $Script:DumplingsModuleRoot '..' '..' 'Modules' 'InstallerParsers' 'GPL2') | Should -BeFalse
  }

  It 'Should keep task scripts on PackageModule helper names instead of direct CLI calls' {
    $TaskRoot = Join-Path $Script:DumplingsRepositoryRoot 'Tasks'
    $TaskPieces = @(Get-ChildItem -Path $TaskRoot -Filter '*.ps1' -Recurse -File)
    $RawBootstrapperExtractionTasks = @($TaskPieces | Where-Object { (Get-Content $_.FullName -Raw) -match '\bExpand-(?:AdvancedInstaller|InstallShield)\b' } | Select-Object -ExpandProperty DirectoryName -Unique)
    $DirectCliTasks = @($TaskPieces | Where-Object { (Get-Content $_.FullName -Raw) -match 'InstallerParsers\\GPL|InstallerParsers\.GPL|Cli\.ps1' })

    $RawBootstrapperExtractionTasks.Count | Should -Be 0
    $DirectCliTasks.Count | Should -Be 0
  }

  It 'Should keep Apache-2.0 wrappers from importing the GPL modules into the shared session' {
    $NsisContent = Get-Content (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'NSIS.psm1') -Raw
    $InnoContent = Get-Content (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'Inno.psm1') -Raw
    $AdvancedInstallerContent = Get-Content (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'AdvancedInstaller.psm1') -Raw
    $BridgeContent = Get-Content (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerBridge.psm1') -Raw

    $NsisContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $InnoContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $AdvancedInstallerContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $BridgeContent | Should -Match 'pwsh'
    $BridgeContent | Should -Match 'Cli\.ps1'
  }
}
