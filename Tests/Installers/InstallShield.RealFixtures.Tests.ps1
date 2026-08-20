. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldTestSetup.ps1')

Describe 'InstallShield real installer fixtures' -Tag 'RealFixture', 'Network' {
  It 'Should expose the PackageForTheWeb launch chain without executing it' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'U90Ladder_6_6_45.exe')
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent U90 Ladder PackageForTheWeb fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.ContainerFormat | Should -Be 'PackageForTheWeb Cabinet'
      $Info.PackageForTheWebInfo.Product | Should -Be 'U90Ladder'
      $Info.PackageForTheWebInfo.NestedSetupPath | Should -Be 'Setup.exe'
      $Info.PackageForTheWebInfo.NestedPayloadPath | Should -Be 'setup.inx'
      $Info.PackageForTheWebInfo.NestedPayloadKind | Should -Be 'InstallScript program'
      $Info.PackageForTheWebInfo.LaunchChain.Stage | Should -Be @('PackageForTheWeb', 'InstallShield setup launcher')
      $Info.PackageForTheWebInfo.LaunchChain[0].Arguments | Should -BeNullOrEmpty
      $Info.InstallShieldRelease.ReleaseName | Should -Be 'InstallShield Professional 6'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Wrapper/PackageForTheWeb'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Cabinet6/AnsiCatalog'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'Script/aLuZ'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the AntRad installer' {
    $Fixture = Get-InstallerFixture -Name 'antrad_setup.exe' -Url 'https://pathloss.com/antrad_setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'antrad-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.SetupIniPath | Should -Be 'Setup.ini'
      $Info.MsiPayloadSelection.SelectionMethod | Should -Be 'SetupIni'
      $Info.MsiPayloadSelection.PackageName | Should -Be 'AntRad.msi'
      $Info.SelectedMsiPath | Should -Be 'AntRad.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'AntRad.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'AntRad'
      $MsiInfo.DisplayVersion | Should -Be '5.01.05'
      $MsiInfo.ProductCode | Should -Be '{9F6A3279-53F2-47C4-8FC8-3149620498EA}'
      $MsiInfo.UpgradeCode | Should -Be '{6767F0A3-5CD9-4B6F-90C4-693DADF557D8}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract the large AVer MSI with bounded memory' -Skip:($env:DUMPLINGS_RUN_LARGE_INSTALLER_TESTS -ne '1') {
    $Archive = Get-InstallerFixture -Name 'AVerTouch.zip' -Url 'https://download.aver.com/AVerTouchWindows/check4Update/AVerTouch.zip' -Sha256 '7E448DF1F753ED22C39DC8F840881622B6CFB294CDB071138D911481F19C51EC'
    $Fixture = Join-Path $Script:FixtureDirectory 'AVerTouchQt.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'aver-touch-expanded'
    $FixtureHash = '2D9C3D01E3284893DA78BF3FD633E699BD71747959B2F37253645D3C9D97252C'

    if (-not (Test-Path -LiteralPath $Fixture) -or (Get-DumplingsTestFixtureHash -Path $Fixture) -ne $FixtureHash) {
      $Zip = [IO.Compression.ZipFile]::OpenRead($Archive)
      try {
        $Entry = $Zip.GetEntry('AVerTouchQt.exe')
        if (-not $Entry) { throw 'The AVer archive does not contain AVerTouchQt.exe.' }
        $InputStream = $Entry.Open()
        $OutputStream = [IO.File]::Create($Fixture)
        try { $InputStream.CopyTo($OutputStream) } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
      } finally {
        $Zip.Dispose()
      }
    }
    Get-DumplingsTestFixtureHash -Path $Fixture | Should -Be $FixtureHash

    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.SelectedMsiPath | Should -Be 'AVerTouch.msi'
      (Get-Item -LiteralPath $MsiInfo.Path).Length | Should -Be 435532288
      $MsiInfo.PackageArchitecture | Should -Be 'x86'
      $MsiInfo.DisplayVersion | Should -Be '1.3.2114.0'
      $MsiInfo.ProductCode | Should -Be '{B16D6CCE-CC0A-4516-8BA8-897E24376A2B}'
      $MsiInfo.UpgradeCode | Should -Be '{2525391D-961E-42A8-B163-22226CAFB2CB}'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the Tachograph File Viewer installer' {
    $Fixture = Get-InstallerFixture -Name 'TachoFileViewer_3_40.exe' -Url 'https://www.prosysdev.com/downloads/TachoFileViewer_3_40.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'tachograph-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.PackageName | Should -Be 'Tachograph File Viewer.msi'
      $Info.SelectedMsiPath | Should -Be 'Tachograph File Viewer.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'Tachograph File Viewer.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'Tachograph File Viewer'
      $MsiInfo.DisplayVersion | Should -Be '3.40'
      $MsiInfo.ProductCode | Should -Be '{AAA4DC80-8FA6-4A8E-AFD2-D82B9CCCA2A8}'
      $MsiInfo.UpgradeCode | Should -Be '{F97E4ADC-C4FE-4253-B342-EC2D8873E27B}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract MSI metadata from the WiFi Sensor Software installer' {
    $Fixture = Get-InstallerFixture -Name 'WiFi Sensor Software.exe' -Url 'https://s3.amazonaws.com/easylogcloud/WiFi%20Sensor%20Software.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'wifi-sensor-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.InstallerType | Should -Be 'InstallShield'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.PackageName | Should -Be 'WiFi Sensor Software.msi'
      $Info.SelectedMsiPath | Should -Be 'WiFi Sensor Software.msi'
      $MsiInfo.SelectedMsiPath | Should -Be 'WiFi Sensor Software.msi'
      $MsiInfo.SelectionMethod | Should -Be 'SetupIni'
      $MsiInfo.DisplayName | Should -Be 'WiFi Sensor Software'
      $MsiInfo.DisplayVersion | Should -Be '1.40.15'
      $MsiInfo.ProductCode | Should -Be '{EF49368B-13B1-4F5B-B453-83C725D31F82}'
      $MsiInfo.UpgradeCode | Should -Be '{60BF28CD-D862-47B9-A3C1-A361DB53CF77}'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should select the Setup.ini MSI instead of the first wildcard match' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-selection'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $null = New-Item -Path (Join-Path $ExpandedPath 'payload') -ItemType Directory -Force
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'First.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'payload\Selected.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllText((Join-Path $ExpandedPath 'Setup.ini'), @'
[Startup]
PackageName=Selected.msi

[Selected.msi]
Type=1
Location=payload\Selected.msi
'@)

      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath } {
        $MsiFiles = @(Get-ChildItem -LiteralPath $ExpandedPath -Filter '*.msi' -Recurse -File)
        $Selection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExpandedPath -MsiFile $MsiFiles
        $Installer = [pscustomobject]@{
          ExtractedPath       = $ExpandedPath
          MsiPayloadSelection = $Selection
        }
        $Selected = Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false

        $Selection.SelectionMethod | Should -Be 'SetupIni'
        $Selection.SelectedMsiPath | Should -Be 'payload\Selected.msi'
        $Selected.Name | Should -Be 'Selected.msi'
        { Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern 'First.msi' -NameWasSpecified $true } | Should -Throw '*does not match the requested pattern*'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should follow an InstallShield 11.5 external-media Setup.ini without scanning sibling files' {
    $FixtureRoot = Join-Path $Script:InstallShieldBuilderRoot '11.5\Differential\BuilderInstaller'
    $Fixture = Join-Path $FixtureRoot 'setup.exe'
    $MsiFixture = Join-Path $FixtureRoot 'InstallShield1150.msi'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf) -or
      -not (Test-Path -LiteralPath $MsiFixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield 11.5 external-media fixture is unavailable.'
      return
    }

    $ExpandedPath = Join-Path $Script:FixtureDirectory 'installshield-115-external-expanded'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.HasMsi | Should -BeTrue
      $Info.MsiPayloadSelection.SourceKind | Should -Be 'ExternalSibling'
      $Info.SetupIniPath | Should -Be 'Setup.ini'
      $Info.SelectedMsiPath | Should -Be 'InstallShield1150.msi'
      $Info.MsiFiles | Should -Contain (Get-Item -LiteralPath $MsiFixture).FullName
      $MsiInfo.Path | Should -Be (Get-Item -LiteralPath $MsiFixture).FullName
      $MsiInfo.DisplayName | Should -Be 'InstallShield 11.5'
      $MsiInfo.DisplayVersion | Should -Be '11.50.0000'
      $MsiInfo.ProductCode | Should -Be '{97033B64-7CE1-428F-BD7F-101D26C9AF9E}'
      $MsiInfo.UpgradeCode | Should -Be '{474F074C-7A6F-45A7-9550-8D5ECE5938DE}'
      $MsiInfo.InstallShieldProjectType | Should -Be 'Basic MSI'
      $Info.InstallShieldRelease.ProductVersion | Should -Be '11.5'
      $Info.InstallShieldStructuralRoutes.RouteId | Should -Contain 'MSI/Basic'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should not substitute an unrelated sibling MSI for a missing Setup.ini package' {
    $MediaRoot = Join-Path $TestDrive 'external-media-missing-package'
    $ExpandedPath = Join-Path $TestDrive 'external-media-missing-package-expanded'
    $null = New-Item -Path $MediaRoot -ItemType Directory -Force
    $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
    [IO.File]::WriteAllBytes((Join-Path $MediaRoot 'setup.exe'), [byte[]]@(0x4D, 0x5A))
    [IO.File]::WriteAllBytes((Join-Path $MediaRoot 'Unrelated.msi'), [byte[]]@(0))
    [IO.File]::WriteAllText((Join-Path $MediaRoot 'Setup.ini'), @'
[Startup]
PackageName=Missing.msi

[Missing.msi]
Location=payload\Missing.msi
'@)

    InModuleScope InstallShield -Parameters @{ MediaRoot = $MediaRoot; ExpandedPath = $ExpandedPath } {
      $Selection = Get-InstallShieldExternalMediaSelection `
        -InstallerPath (Join-Path $MediaRoot 'setup.exe') -ExtractedPath $ExpandedPath

      $Selection.SelectionMethod | Should -Be 'SetupIniUnresolved'
      $Selection.SourceKind | Should -Be 'ExternalOrMissing'
      $Selection.SelectedMsiPath | Should -BeNullOrEmpty
      $Selection.Diagnostics.Message | Should -Contain "Setup.ini selects 'Missing.msi', but that MSI path was not extracted."
    }
  }

  It 'Should reject an unresolved multi-MSI payload without an explicit override' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-ambiguous'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'First.msi'), [byte[]]@(0))
      [System.IO.File]::WriteAllBytes((Join-Path $ExpandedPath 'Second.msi'), [byte[]]@(0))

      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath } {
        $MsiFiles = @(Get-ChildItem -LiteralPath $ExpandedPath -Filter '*.msi' -File)
        $Selection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExpandedPath -MsiFile $MsiFiles
        $Installer = [pscustomobject]@{
          ExtractedPath       = $ExpandedPath
          MsiPayloadSelection = $Selection
        }

        $Selection.SelectionMethod | Should -Be 'Unresolved'
        $Selection.SelectedMsiPath | Should -BeNullOrEmpty
        { Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false } | Should -Throw '*selection is ambiguous*'
        (Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern 'Second.msi' -NameWasSpecified $true).Name | Should -Be 'Second.msi'
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
