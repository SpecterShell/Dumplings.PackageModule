. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive
}

Describe 'InstallAware static parser' {
  It 'Should require InstallAware project evidence in a validated embedded 7z' {
    $ArchiveBytes = [Convert]::FromBase64String('N3q8ryccAASC6rZeGQAAAAAAAABqAAAAAAAAAIO0oUEBABTvu79NWiBzeW50aGV0aWMgc2V0dXAAAQQGAAEJGQAHCwEAASEhAQAMFQAICgEliOZUAAAFARkMAAAAAAAAAAAAAAAAESUARQB4AGEAbQBwAGwAZQBfAFMAZQB0AHUAcAAuAGUAeABlAAAAFAoBALa5/FNLEN0BFQYBACAAAAAAAA==')
    $FixturePath = Join-Path $Script:FixtureDirectory 'installaware-archive.bin'
    [IO.File]::WriteAllBytes($FixturePath, ([byte[]]::new(1024) + $ArchiveBytes))

    InModuleScope InstallAware -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $ArchiveData = Get-InstallAwareArchiveData -Path $FixturePath
      $ArchiveData.Range.Offset | Should -Be 1024
      $ArchiveData.Entries.FullName | Should -Contain 'Example_Setup.exe'
      $ArchiveData.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
    }
  }
}
