. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive

  function ConvertTo-TestQSetupRecord {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Content, [switch]$Required)
    $RequiredMarker = if ($Required) { '*' } else { '' }
    $Header = [Text.Encoding]::ASCII.GetBytes("|$Name$RequiredMarker|123456|")
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try { $Encoder.Write($Header, 0, $Header.Length); $Encoder.Write($Content, 0, $Content.Length) } finally { $Encoder.Dispose() }
    return [BitConverter]::GetBytes([uint32]$Compressed.Length) + $Compressed.ToArray()
  }

  function ConvertTo-TestQSetupFooter {
    param([Parameter(Mandatory)][uint32]$OverlayOffset, [Parameter(Mandatory)][uint32]$RecordCount)
    $Footer = [byte[]]::new(74)
    foreach ($Value in @(
        @{ Offset = 0; Value = [uint32]0x201 },
        @{ Offset = 4; Value = $OverlayOffset },
        @{ Offset = 8; Value = $RecordCount },
        @{ Offset = 12; Value = [uint32]0x4A3B2C1D },
        @{ Offset = 16; Value = [uint32]1234 },
        @{ Offset = 70; Value = [uint32]$Footer.Length }
      )) {
      [Buffer]::BlockCopy([BitConverter]::GetBytes($Value.Value), 0, $Footer, $Value.Offset, 4)
    }
    return $Footer
  }
}

Describe 'QSetup static parser' {
  It 'Should parse explicit Setup.txt ARP, scope, architecture, and association directives' {
    $SetupText = @'
SET_PROG_NAME(Example QSetup Product);
SET_PROJECT_NAME(ExampleProject);
SET_PROG_VERSION(4.5.6);
SET_COMPANY_NAME(Example Publisher);
SET_COMPOSER_BUILD(12.0.0.5);
SET_TARGET_DIR(<ProgramFiles>\Example);
SET_PROG_EXE_NAME(<Application Folder>\Example.exe);
SET_CREATE_UNINSTALL;
SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS;
SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME(Example QSetup ARP);
SET_ALL_USERS;
SET_ALLOWED_OS(10.64,11.64);
SET_ADD_ASSOCIATION_ITEM(|Example.Document|Example document|.example|Example|<Application Folder>\Example.exe|<Application Folder>\Example.exe|0|Create|Remove||);
SET_PERFORM_EXECUTE_OP(*||Install prerequisite|Setup Start|10|UnConditional|0|0|File Found||0|0|0|File Found||0|0|0|File Found||1|Run Executable and Wait||0|Display Message||0|Display Message||0|Display Message||0|Display Message||0|Display Message||0|*|||=||||=||||=|||<SrcDir>\runtime.exe|/quiet /norestart||||||||||||||||||*);
'@
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath

      $Info.DisplayName | Should -Be 'Example QSetup ARP'
      $Info.DisplayVersion | Should -Be '4.5.6'
      $Info.Publisher | Should -Be 'Example Publisher'
      $Info.ProductCode | Should -Be 'Example QSetup ARP'
      $Info.Scope | Should -Be 'machine'
      $Info.SupportedArchitectures | Should -Be @('x64')
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.FileExtensions | Should -Be @('example')
      $Info.Records.Name | Should -Be @('Engine.exe', 'Setup.txt')
      $Info.Warnings | Should -BeNullOrEmpty
      $Info.Notices | Should -HaveCount 1
      $Info.ExecutionActions | Should -HaveCount 1
      $Info.ExecutedPayloads | Should -HaveCount 1
      $Info.ExecutedPayloads[0].Command | Should -Be '<SrcDir>\runtime.exe'
      $Info.ExecutedPayloads[0].Parameters | Should -Be '/quiet /norestart'
    }
  }

  It 'Should stop at the validated QSetup footer instead of treating it as a compressed record' {
    $SetupText = "SET_PROG_NAME(Footer Product);`r`nSET_PROG_VERSION(1.0);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_ALL_USERS;"
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 2
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-footer-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath
      $Info.Warnings | Should -BeNullOrEmpty
      $Info.Records | Should -HaveCount 2
      $Info.PackageFooter.DeclaredRecordCount | Should -Be 2
      $Info.Certificate | Should -BeNullOrEmpty

      $Destination = Join-Path $TestDrive 'qsetup-footer-extraction'
      $Files = Expand-QSetupInstaller -Path $FixturePath -DestinationPath $Destination -Name 'Setup.txt' -CollisionAction Error
      $Files | Should -HaveCount 1
      $Files[0].Name | Should -Be 'Setup.txt'
    }
  }

  It 'Should retain malformed execution-action records as warnings' {
    InModuleScope QSetup {
      $Directive = @{ SET_PERFORM_EXECUTE_OP = [Collections.Generic.List[object]]@('unsupported-layout') }
      $Result = Get-QSetupExecutionActionInfo -Directive $Directive
      $Result.Actions | Should -BeNullOrEmpty
      $Result.ExecutedPayloads | Should -BeNullOrEmpty
      $Result.Warnings | Should -HaveCount 1
    }
  }

  It 'Should parse the complete signed AGTEK execution-action layout' {
    $RelativePath = 'Installers\QSetup\AGTEK.Trackwork\2.25.5.6\Trackwork4D225.5.6x64.exe'
    $Sha256 = '6EC7D39B466DF83024E1320A8755669CFA7FEB104166D615480D2FD17F42FE62'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      if ($env:DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES -eq '1') {
        $Fixture = Get-DumplingsTestFixture -RelativePath $RelativePath -Uri 'https://agtek.s3.amazonaws.com/Agtek/n9KWMWYsnSRr' -Sha256 $Sha256
      } else {
        Set-ItResult -Skipped -Because 'Set DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES=1 to cache the 125 MiB signed QSetup regression.'
        return
      }
    }

    $Info = Get-QSetupInfo -Path $Fixture
    $Info.Warnings | Should -BeNullOrEmpty
    $Info.PackageFooter.DeclaredRecordCount | Should -Be 241
    $Info.Records | Should -HaveCount 241
    $Info.Certificate.Offset | Should -BeGreaterThan $Info.PackageFooter.Offset
    $Info.ExecutionActions.Count | Should -BeGreaterThan 10
    $Info.ExecutedPayloads.Command | Should -Contain '<SrcDir>\vc100redist_x86.exe'
    $Info.ExecutedPayloads.Parameters | Should -Contain '/passive /norestart'
  }
}
