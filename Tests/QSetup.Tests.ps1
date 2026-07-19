BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Compression', 'Archive', 'PE', 'RegistryAssociations', 'QSetup')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\AdditionalGenericExeParsers'

  function ConvertTo-TestQSetupRecord {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Content, [switch]$Required)
    $RequiredMarker = if ($Required) { '*' } else { '' }
    $Header = [Text.Encoding]::ASCII.GetBytes("|$Name$RequiredMarker|123456|")
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try { $Encoder.Write($Header, 0, $Header.Length); $Encoder.Write($Content, 0, $Content.Length) } finally { $Encoder.Dispose() }
    return [BitConverter]::GetBytes([uint32]$Compressed.Length) + $Compressed.ToArray()
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
    }
  }
}
