BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallForge.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\InstallForge'
  $Script:FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-installforge.exe'
  [IO.File]::WriteAllBytes($Script:FixturePath, [byte[]](0x4D, 0x5A, 0, 0))
}

Describe 'InstallForge static parser' {
  It 'Should decode base64 UTF-16LE archive path segments' {
    InModuleScope InstallForge {
      ConvertFrom-InstallForgeEncodedPath -Path 'YgBpAG4A/RQB4AGEAbQBwAGwAZQAuAGUAeABlAA==' | Should -Be (Join-Path 'bin' 'Example.exe')
      ConvertFrom-InstallForgeEncodedPath -Path 'YgBpAG4A\empty.empty' | Should -Be (Join-Path 'bin' 'empty.empty')
    }
  }

  It 'Should parse explicit setup metadata and scope without inventing ProductCode' {
    InModuleScope InstallForge -Parameters @{ FixturePath = $Script:FixturePath } {
      param($FixturePath)
      Mock Get-InstallForgeConfigurationArchiveData {
        [pscustomobject]@{
          ArchivePath = Join-Path $TestDrive 'missing-config.7z'
          Entries     = @([pscustomobject]@{ FullName = 'SC.dat'; EncodedName = 'UwBDAC4AZABhAHQA'; Length = 512 })
        }
      }
      Mock Read-InstallForgeConfigurationText {
        @'
[Setup]
Appname = Example InstallForge Product
Version = 2.3.4
Company = Example Vendor
Website1 = https://example.test
InstallDir = <ProgramFiles>\Example
Uninstaller = 1
UninstallerFilename = Remove Example
ProgramRun = <InstallPath>\Example.exe
'@
      }
      Mock Get-InstallForgePayloadArchiveData {
        [pscustomobject]@{
          ArchivePath = Join-Path $TestDrive 'missing-payload.7z'
          Offset      = 4096
          Entries     = @(
            [pscustomobject]@{ FullName = 'Example.exe'; EncodedName = 'RQB4AGEAbQBwAGwAZQAuAGUAeABlAA=='; Length = 10 },
            [pscustomobject]@{ FullName = 'bin\empty.empty'; EncodedName = 'YgBpAG4A\empty.empty'; Length = 1 }
          )
        }
      }

      $Info = Get-InstallForgeInfo -Path $FixturePath

      $Info.DisplayName | Should -Be 'Example InstallForge Product'
      $Info.DisplayVersion | Should -Be '2.3.4'
      $Info.Publisher | Should -Be 'Example Vendor'
      $Info.Scope | Should -Be 'machine'
      $Info.SupportedScopes | Should -Be @('machine')
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.SupportsSilentInstallation | Should -BeFalse
      $Info.ExtractedFiles | Should -Be @('Example.exe')
    }
  }

  It 'Should resolve user scope only from explicit user-directory tokens' {
    InModuleScope InstallForge {
      Resolve-InstallForgeScope -InstallDirectory '<LocalAppData>\Example' | Should -Be 'user'
      Resolve-InstallForgeScope -InstallDirectory '<ProgramFiles>\Example' | Should -Be 'machine'
      Resolve-InstallForgeScope -InstallDirectory 'D:\Example' | Should -BeNullOrEmpty
    }
  }
}
