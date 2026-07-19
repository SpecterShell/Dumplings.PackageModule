BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'ActualInstaller.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\GenericExeParsers'

  function New-TestZipFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Entry)
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    $Archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($Name in $Entry.Keys) {
        $ZipEntry = $Archive.CreateEntry($Name)
        $Writer = [IO.StreamWriter]::new($ZipEntry.Open(), [Text.Encoding]::UTF8)
        try { $Writer.Write([string]$Entry[$Name]) } finally { $Writer.Dispose() }
      }
    } finally { $Archive.Dispose() }
  }

  function New-TestEmbeddedZipFixture {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ZipPath)
    $Fixture = Join-Path $Script:FixtureDirectory $Name
    Remove-Item -LiteralPath $Fixture -Force -ErrorAction SilentlyContinue
    $Stub = [byte[]](0x4d, 0x5a, 0, 0, 0, 0, 0, 0)
    $Payload = [IO.File]::ReadAllBytes($ZipPath)
    [IO.File]::WriteAllBytes($Fixture, $Stub + $Payload)
    return $Fixture
  }
}

Describe 'Actual Installer static parser' {
  It 'Should parse aisetup.ini and reject build-time version placeholders' {
    $Zip = Join-Path $Script:FixtureDirectory 'actual.zip'
    New-TestZipFile -Path $Zip -Entry @{ 'aisetup.ini' = "[Setup]`nGUID={33333333-3333-3333-3333-333333333333}`nAppName=Example Actual`nAppVersion=<V>`nCompanyName=Example Vendor`nInstallDir=<AppData>\\Example`nAltInstallDir=<ProgramFiles>\\Example`nShowAddRemove=1`nUninstallFile=Uninstall.exe`n[Registry]`nSetting=Value"; 'Englishai.lng' = 'language' }
    $Fixture = New-TestEmbeddedZipFixture -Name 'actual.exe' -ZipPath $Zip

    $Info = Get-ActualInstallerInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{33333333-3333-3333-3333-333333333333}'
    $Info.DisplayName | Should -Be 'Example Actual'
    $Info.DisplayVersion | Should -BeNullOrEmpty
    $Info.Publisher | Should -Be 'Example Vendor'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.RegistryWrites | Should -HaveCount 1
  }
}
