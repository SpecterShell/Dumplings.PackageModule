BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'MSI.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'NSIS.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Inno.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'AdvancedInstaller.psm1') -Force

  $Script:FixtureDirectory = Join-Path $env:TEMP 'DumplingsInstallerBridgeTests'
  $null = New-Item -Path $Script:FixtureDirectory -ItemType Directory -Force

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [switch]$UseSourceForgeMetaRefresh
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    if (Test-Path -LiteralPath $FixturePath) { return $FixturePath }

    if ($UseSourceForgeMetaRefresh) {
      $Page = Invoke-WebRequest -Uri $Url
      $MetaRefresh = [regex]::Match($Page.Content, 'url=([^"&]+(?:&amp;[^"<]+)*)')
      if (-not $MetaRefresh.Success) { throw "Failed to resolve the SourceForge download URL for $Url" }
      $Url = [System.Web.HttpUtility]::HtmlDecode($MetaRefresh.Groups[1].Value)
    }

    Invoke-WebRequest -Uri $Url -OutFile $FixturePath
    return $FixturePath
  }
}

Describe 'Installer bridge' {
  It 'Should call the InstallerParsers NSIS parser through the MIT wrapper' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'alist-desktop'
    $Info.DisplayVersion | Should -Be '3.60.0'
  }

  It 'Should return FileInfo objects from the InstallerParsers Inno extraction bridge' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'myob-bridge-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'BK5WIN.EXE'

      $Extracted | Should -HaveCount 1
      $Extracted[0] | Should -BeOfType ([System.IO.FileInfo])
      $Extracted[0].VersionInfo.FileVersion | Should -Be '5.55.3.7499'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should read MSI metadata through the InstallerParsers Advanced Installer bridge' {
    $Fixture = Get-InstallerFixture -Name 'TINspireComputerLink-3.9.0.455.exe' -Url 'https://education.ti.com/download/en/ed-tech/82035809F7E6474099944056CCB01C20/AC3AAE51297B4902B6B6CA005B8391F0/TINspireComputerLink-3.9.0.455.exe'
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Path $Fixture -Name 'ComputerLink.msi'

    $MsiInfo.ProductVersion | Should -Be '3.9.0.455'
    $MsiInfo.ProductCode | Should -Be '{6C5AC088-3136-4043-8985-8B0772A9580E}'
  }
}

Describe 'Bridge regressions' {
  It 'Should keep parser modules outside the shared Dumplings session autoload path' {
    Test-Path (Join-Path $PSScriptRoot '..' '..' '..' 'Modules' 'InstallerParsers' 'Index.ps1') | Should -BeFalse
    Test-Path (Join-Path $PSScriptRoot '..' '..' '..' 'Modules' 'InstallerParsers' 'GPL3') | Should -BeFalse
    Test-Path (Join-Path $PSScriptRoot '..' '..' '..' 'Modules' 'InstallerParsers' 'GPL2') | Should -BeFalse
  }

  It 'Should keep task scripts on MIT helper names instead of direct CLI calls' {
    $TaskRoot = Join-Path $PSScriptRoot '..' '..' '..' 'Tasks'
    $NsisTasks = @(Get-ChildItem -Path $TaskRoot -Filter 'Script.ps1' -Recurse -File | Where-Object { (Get-Content $_.FullName -Raw) -match '\bGet-NSISInfo\b' })
    $InnoTasks = @(Get-ChildItem -Path $TaskRoot -Filter 'Script.ps1' -Recurse -File | Where-Object { (Get-Content $_.FullName -Raw) -match '\bGet-InnoInfo\b|\bExpand-InnoInstaller\b' })
    $AdvancedInstallerTasks = @(Get-ChildItem -Path $TaskRoot -Filter 'Script.ps1' -Recurse -File | Where-Object { (Get-Content $_.FullName -Raw) -match '\bExpand-AdvancedInstaller\b' })
    $DirectCliTasks = @(Get-ChildItem -Path $TaskRoot -Filter 'Script.ps1' -Recurse -File | Where-Object { (Get-Content $_.FullName -Raw) -match 'InstallerParsers\\GPL|InstallerParsers\.GPL|Cli\.ps1' })

    $NsisTasks.Count | Should -Be 71
    $InnoTasks.Count | Should -Be 3
    $AdvancedInstallerTasks.Count | Should -Be 36
    $DirectCliTasks.Count | Should -Be 0
  }

  It 'Should keep MIT wrappers from importing the GPL modules into the shared session' {
    $NsisContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'NSIS.psm1') -Raw
    $InnoContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'Inno.psm1') -Raw
    $AdvancedInstallerContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'AdvancedInstaller.psm1') -Raw
    $BridgeContent = Get-Content (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallerBridge.psm1') -Raw

    $NsisContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $InnoContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $AdvancedInstallerContent | Should -Not -Match 'Import-Module .*InstallerParsers'
    $BridgeContent | Should -Match 'pwsh'
    $BridgeContent | Should -Match 'Cli\.ps1'
  }
}
