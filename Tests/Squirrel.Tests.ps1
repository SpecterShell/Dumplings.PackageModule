BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Squirrel.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\Squirrel'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }
}

Describe 'Squirrel parser' {
  It 'Should convert Squirrel RELEASES feed content without fetching it' {
    $Releases = @'
0123456789abcdef0123456789abcdef01234567 https://updates.example.test/win/App-1.2.3-full.nupkg?token=dynamic 12345 # 50%
89abcdef0123456789abcdef0123456789abcdef App-1.2.2-delta.nupkg 2345
'@
    $Entries = $Releases | ConvertFrom-SquirrelReleases

    $Entries | Should -HaveCount 2
    $Entries[0].Version | Should -Be '1.2.3'
    $Entries[0].Sha1 | Should -Be '0123456789abcdef0123456789abcdef01234567'
    $Entries[0].Filename | Should -Be 'App-1.2.3-full.nupkg'
    $Entries[0].Filesize | Should -Be 12345
    $Entries[0].IsDelta | Should -BeFalse
    $Entries[0].BaseUrl | Should -Be 'https://updates.example.test/win/'
    $Entries[0].Query | Should -Be '?token=dynamic'
    $Entries[0].StagingPercentage | Should -Be 0.5
    $Entries[1].IsDelta | Should -BeTrue
  }

  It 'Should read nested nupkg metadata from the Sourcetree installer' {
    $Fixture = Get-InstallerFixture -Name 'SourceTreeSetup-3.4.31.exe' -Url 'https://product-downloads.atlassian.com/software/sourcetree/windows/ga/SourceTreeSetup-3.4.31.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'SourceTree'
    $Info.DisplayName | Should -Be 'SourceTree'
    $Info.DisplayVersion | Should -Be '3.4.31'
    $Info.Publisher | Should -Be 'Atlassian'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'SourceTree-3.4.31-full.nupkg'
  }

  It 'Should read nested nupkg metadata from the Dialpad installer' {
    $Fixture = Get-InstallerFixture -Name 'DialpadSetup-2605.1.0_x64.exe' -Url 'https://storage.googleapis.com/dialpad_native/stable/win32/x64/DialpadSetup-2605.1.0_x64.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'dialpad'
    $Info.DisplayName | Should -Be 'Dialpad'
    $Info.DisplayVersion | Should -Be '2605.1.0'
    $Info.Publisher | Should -Be 'Dialpad'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'dialpad-2605.1.0-full.nupkg'
  }

  It 'Should read direct nuspec metadata from the Appeee installer' {
    $Fixture = Get-InstallerFixture -Name 'AppeeeSetup.exe' -Url 'https://web.appeee.nl/Files/UpdateWinApp/appeee/AppeeeSetup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Velopack/Squirrel nupkg'
    $Info.ProductCode | Should -Be 'Appeee'
    $Info.DisplayName | Should -Be 'Appeee'
    $Info.DisplayVersion | Should -Be '2.0.0'
    $Info.Publisher | Should -Be 'Appeee'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -BeNullOrEmpty
  }

  It 'Should read resource nupkg metadata from the Amazon Chime installer' {
    $Fixture = Get-InstallerFixture -Name 'Chime-5.23.32138.exe' -Url 'https://clients.chime.aws/win-nme/Chime-5.23.32138.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'AmazonChime'
    $Info.DisplayName | Should -Be 'Amazon Chime'
    $Info.DisplayVersion | Should -Be '5.23.32138'
    $Info.Publisher | Should -Be 'Amazon.com Services LLC'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'AmazonChime-5.23.32138-full.nupkg'
  }

  It 'Should read resource nupkg metadata from the Toggl Track installer' {
    $Fixture = Get-InstallerFixture -Name 'TogglTrack-windows64.exe' -Url 'https://toggl.com/track/toggl-desktop/downloads/windows/stable/TogglTrack-windows64.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'TogglTrack'
    $Info.DisplayName | Should -Be 'Toggl Track'
    $Info.DisplayVersion | Should -Match '^\d+\.\d+\.\d+$'
    $Info.Publisher | Should -Be 'Toggl OÜ'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be "TogglTrack-$($Info.DisplayVersion)-full.nupkg"
  }

  It 'Should read nested nupkg metadata from the Slack installer' {
    $Fixture = Get-InstallerFixture -Name 'SlackSetup-4.50.143.exe' -Url 'https://downloads.slack-edge.com/desktop-releases/windows/x64/4.50.143/SlackSetup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'slack'
    $Info.DisplayName | Should -Be 'Slack'
    $Info.DisplayVersion | Should -Be '4.50.143'
    $Info.Publisher | Should -Be 'Slack Technologies Inc.'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'slack-4.50.143-full.nupkg'
  }

  It 'Should read nested nupkg metadata from the Figma installer' {
    $Fixture = Get-InstallerFixture -Name 'Figma-126.6.12.exe' -Url 'https://desktop.figma.com/win/build/Figma-126.6.12.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'Figma'
    $Info.DisplayName | Should -Be 'Figma'
    $Info.DisplayVersion | Should -Be '126.6.12'
    $Info.Publisher | Should -Be 'Figma, Inc.'
    $Info.Scope | Should -Be 'user'
    $Info.NupkgPath | Should -Be 'Figma-126.6.12-full.nupkg'
  }

  It 'Should read nested nupkg metadata from the Discord installer' {
    $Fixture = Get-InstallerFixture -Name 'DiscordSetup-1.0.9244.exe' -Url 'https://dl.discordapp.net/distro/app/stable/win/x64/1.0.9244/DiscordSetup.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Squirrel'
    $Info.Family | Should -Be 'Squirrel'
    $Info.ProductCode | Should -Be 'Discord'
    $Info.DisplayName | Should -Be 'Discord'
    $Info.DisplayVersion | Should -Be '1.0.9244'
    $Info.Publisher | Should -Be 'Discord Inc.'
    $Info.Scope | Should -Be 'user'
    $Info.DefaultInstallLocation | Should -Be '%LocalAppData%\Discord'
    $Info.SuggestedManifestFields.InstallationMetadata.DefaultInstallLocation | Should -Be '%LocalAppData%\Discord'
    $Info.NupkgPath | Should -Be 'Discord-1.0.9244-full.nupkg'
  }

  It 'Should keep the Tower Velopack EXE identity separate from its MSI ARP prefix' {
    $Fixture = Get-InstallerFixture -Name 'Tower-13.1.576.exe' -Url 'https://www.git-tower.com/apps/tower3-win/576-01812649/Tower-13.1.576.exe'
    $Info = Get-SquirrelInfo -Path $Fixture

    $Info.Family | Should -Be 'Velopack/Squirrel nupkg'
    $Info.ProductCode | Should -Be 'Tower'
    $Info.DisplayName | Should -Be 'Tower'
    $Info.DisplayVersion | Should -Be '13.1.576'
    $Info.Publisher | Should -Be 'saas.group'
  }
}
