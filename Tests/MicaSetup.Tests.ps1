BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\MicaSetup'
  $Script:MicaSetupV1Initial = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name 'MicaSetup-v1.0.0.exe' `
    -Uri 'https://github.com/lemutec/MicaSetup/releases/download/v1.0.0/DemoInstaller-MicaSetup.exe' `
    -Sha256 'D1BDD8BE96BF55676D3C7F07643A484067552765C8F7B35154DBE24D8188131A'
  $Script:MicaSetupV1 = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name 'MicaSetup-v1.3.0.exe' `
    -Uri 'https://github.com/lemutec/MicaSetup/releases/download/v1.3.0/DemoInstaller-MicaSetup.exe' `
    -Sha256 'A822E9C6D36018935DEDCE0820CF77CD50E2D3F44CD486C97CDB6847A19EC29B'
  $Script:MicaSetupV2Initial = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name 'MicaSetup-v2.0.0.exe' `
    -Uri 'https://github.com/lemutec/MicaSetup/releases/download/v2.0.0/DemoInstaller-MicaSetup.exe' `
    -Sha256 'DCB73086BC94176E82B55E6CD66CAC8E585503A774F08FD119A335529C626B65'
  $Script:MicaSetupV2 = Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name 'MicaSetup-v2.5.4.exe' `
    -Uri 'https://github.com/lemutec/MicaSetup/releases/download/v2.5.4/MicaSetup_v2.5.4.exe' `
    -Sha256 '47BE125A67DABA58924FE581DCE87502C889B110F6CEC1446B4E7DCABF9748AC'
}

Describe 'MicaSetup managed structure detection' {
  It 'requires the CLR host model and WPF publish archive rather than marker strings' {
    Test-MicaSetupInstaller -Path $Script:MicaSetupV1 | Should -BeTrue
    Test-MicaSetupInstaller -Path $Script:MicaSetupV2 | Should -BeTrue
    Test-MicaSetupInstaller -Path $Script:MicaSetupV1Initial | Should -BeTrue
    Test-MicaSetupInstaller -Path $Script:MicaSetupV2Initial | Should -BeTrue

    $MarkerOnly = Join-Path $TestDrive 'marker-only.exe'
    Copy-Item -LiteralPath (Get-Process -Id $PID).Path -Destination $MarkerOnly
    $Stream = [IO.File]::Open($MarkerOnly, 'Append', 'Write', 'Read')
    try {
      $Bytes = [Text.Encoding]::UTF8.GetBytes('MicaSetup.Option UseOptions resources/setups/publish.7z')
      $Stream.Write($Bytes)
    } finally { $Stream.Dispose() }
    Test-MicaSetupInstaller -Path $MarkerOnly | Should -BeFalse
  }

  It 'restores caller-owned stream position while enumerating bounded nested resources' {
    InModuleScope MicaSetup -Parameters @{ Installer = $Script:MicaSetupV2 } {
      $Stream = [IO.File]::OpenRead($Installer)
      $Stream.Position = 37
      try {
        $Info = Get-MicaSetupManagedInfo -Stream $Stream
        $Info.Resources.Name | Should -Contain 'resources/setups/publish.7z'
        $Info.Resources.Name | Should -Contain 'resources/setups/uninst.exe'
        $Stream.Position | Should -Be 37
      } finally { $Stream.Dispose() }
    }
  }

  It 'rejects the same CLR and resource structures when the PE is marked as a DLL' {
    $DllImage = Join-Path $TestDrive 'mica-library.dll'
    Copy-Item -LiteralPath $Script:MicaSetupV2 -Destination $DllImage
    $Stream = [IO.File]::Open($DllImage, 'Open', 'ReadWrite', 'Read')
    try {
      $DosHeader = [byte[]]::new(64)
      $null = $Stream.Read($DosHeader, 0, $DosHeader.Length)
      $PeOffset = [BitConverter]::ToInt32($DosHeader, 0x3C)
      $CharacteristicsOffset = $PeOffset + 22
      $Stream.Position = $CharacteristicsOffset
      $CharacteristicsBytes = [byte[]]::new(2)
      $null = $Stream.Read($CharacteristicsBytes, 0, 2)
      $Characteristics = [BitConverter]::ToUInt16($CharacteristicsBytes, 0) -bor 0x2000
      $Stream.Position = $CharacteristicsOffset
      $Stream.Write([BitConverter]::GetBytes([uint16]$Characteristics))
    } finally { $Stream.Dispose() }

    Test-MicaSetupInstaller -Path $DllImage | Should -BeFalse
  }

  It 'rejects a truncated managed resource range' {
    $Truncated = Join-Path $TestDrive 'truncated-resource.exe'
    Copy-Item -LiteralPath $Script:MicaSetupV2 -Destination $Truncated
    $Payload = InModuleScope MicaSetup -Parameters @{ Installer = $Truncated } {
      $Stream = [IO.File]::OpenRead($Installer)
      try {
        (Get-MicaSetupManagedInfo -Stream $Stream).Resources.Where({ $_.Name -ieq 'resources/setups/publish.7z' }, 'First')[0]
      } finally { $Stream.Dispose() }
    }
    $Stream = [IO.File]::Open($Truncated, 'Open', 'ReadWrite', 'Read')
    try { $Stream.SetLength($Payload.Offset + 8) } finally { $Stream.Dispose() }

    Test-MicaSetupInstaller -Path $Truncated | Should -BeFalse
  }
}

Describe 'MicaSetup static installer evidence' {
  It 'covers the Pack, legacy Option, and modern Option configuration models' {
    $Pack = Get-MicaSetupInfo -Path $Script:MicaSetupV1Initial
    $LegacyOption = Get-MicaSetupInfo -Path $Script:MicaSetupV2Initial
    $ModernOption = Get-MicaSetupInfo -Path $Script:MicaSetupV2

    $Pack.ConfigurationModel | Should -Be 'Pack'
    $Pack.BuilderGeneration | Should -Be 'v1'
    $Pack.DisplayVersion | Should -Be '1.0.0.0'
    $Pack.Shortcuts.Location | Should -Be @('Desktop')
    $Pack.FirewallRules | Should -BeNullOrEmpty
    $LegacyOption.ConfigurationModel | Should -Be 'OptionLegacy'
    $LegacyOption.BuilderGeneration | Should -Be 'v1'
    $ModernOption.ConfigurationModel | Should -Be 'OptionModern'
    $ModernOption.BuilderGeneration | Should -Be 'v2'
  }

  It 'parses the official v1 generation as an elevated machine installer' {
    $Info = Get-MicaSetupInfo -Path $Script:MicaSetupV1

    $Info.BuilderGeneration | Should -Be 'v1'
    $Info.ProductCode | Should -Be 'MicaApp'
    $Info.DisplayName | Should -Be 'MicaApp'
    $Info.DisplayVersion | Should -Be '1.3.0.0'
    $Info.Publisher | Should -Be 'Lemutec'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\MicaApp'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.RegistryWrites[0].Hive | Should -Be 'HKEY_LOCAL_MACHINE'
    ($Info.RegistryWrites | Where-Object Name -EQ 'SystemComponent').Value | Should -Be 0
    $Info.InstallModes | Should -Be @('interactive')
    $Info.InstallerSwitches.Count | Should -Be 0
    $Info.PayloadFiles.Count | Should -BeGreaterThan 0
    $Info.PayloadArchitectures | Should -Not -Contain 'neutral'
  }

  It 'parses the official v2 generation and resolves option-property metadata references' {
    $Info = Get-MicaSetupInfo -Path $Script:MicaSetupV2

    $Info.BuilderGeneration | Should -Be 'v2'
    $Info.TargetFramework | Should -Match '^\.NETFramework,Version='
    $Info.RequestedExecutionLevel | Should -Be 'requireAdministrator'
    $Info.ProductCode | Should -Be 'MicaSetup'
    $Info.DisplayName | Should -Be 'MicaSetup'
    $Info.DisplayIcon | Should -Be '%ProgramFiles%\MicaSetup\MICA.exe'
    $Info.UninstallString | Should -Be '%ProgramFiles%\MicaSetup\uninst.exe'
    $Info.RegistryView | Should -Be 'default'
    $Info.EnvironmentChanges.Variable | Should -Contain 'PATH'
    $Info.PayloadEncrypted | Should -BeFalse
    $Info.PayloadDecryptionSucceeded | Should -BeNullOrEmpty
    $Info.CanExpand | Should -BeTrue
    $Info.OptionValues.PSObject.Properties.Name | Should -Not -Contain 'UnpackingPassword'
    $Info.PSObject.Properties.Name | Should -Contain 'UnresolvedExpressions'
    ($Info | ConvertTo-Json -Depth 20) | Should -Not -Match 'constant string \(redacted\).*[^\r\n]*:'
  }

  It 'keeps custom association evidence empty when compiled literal writes are absent' {
    $Info = Get-MicaSetupInfo -Path $Script:MicaSetupV2
    $Info.Protocols | Should -BeNullOrEmpty
    $Info.FileExtensions | Should -BeNullOrEmpty
    Read-ProtocolsFromMicaSetup -Path $Script:MicaSetupV2 | Should -BeNullOrEmpty
    Read-FileExtensionsFromMicaSetup -Path $Script:MicaSetupV2 | Should -BeNullOrEmpty
  }

  It 'treats a proven v2 user route as Uninst.dat state without a visible ProductCode' {
    InModuleScope MicaSetup -Parameters @{ Installer = (Get-Process -Id $PID).Path } {
      $NewOption = {
        param([string]$Name, $Value)
        [pscustomobject]@{ Name = $Name; Value = $Value; IsResolved = $true; Expression = 'synthetic'; Method = 'Fixture::Options'; IlOffset = 0; ArrayLength = -1 }
      }
      $Managed = [pscustomobject]@{
        FileKind = 'Executable'
        HasOptionType = $true; HasUseOptionsMethod = $true; BuilderGeneration = 'v2'; TargetFramework = '.NETFramework,Version=v4.8'
        RequestExecutionLevel = 'user'; UseElevated = $false; Warnings = @(); Evidence = @('synthetic v2 user route')
        Resources = @([pscustomobject]@{ Name = 'resources/setups/publish.7z'; TypeCode = 33; Offset = 0; Length = 1 })
        RegistryWrites = @()
        Options = @(
          & $NewOption 'AppName' 'UserApp'
          & $NewOption 'KeyName' 'UserApp'
          & $NewOption 'ExeName' 'UserApp.exe'
          & $NewOption 'DisplayName' 'User App'
          & $NewOption 'DisplayVersion' '1.0.0'
          & $NewOption 'Publisher' 'Example'
          & $NewOption 'IsCreateRegistryKeys' $true
        )
      }
      Mock Get-MicaSetupManagedInfo { $Managed }
      Mock Open-MicaSetupPayloadArchive { [pscustomobject]@{ Archive = 'synthetic'; Range = $null } }
      Mock Get-MicaSetupPayloadEvidence { [pscustomobject]@{ Catalog = @(); Architectures = @(); ArchitectureInfo = $null; DependencyInfo = $null } }
      Mock Close-MicaSetupPayloadArchive {}

      $Info = Get-MicaSetupInfo -Path $Installer
      $Info.Scope | Should -Be 'user'
      $Info.DefaultInstallLocation | Should -Be '%APPDATA%\UserApp'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
      $Info.RegistryWrites | Should -BeNullOrEmpty
      ($Info.Notices -join "`n") | Should -Match 'Uninst.dat'
    }
  }

  It 'retains hidden ARP writes and projects literal custom class registrations' {
    InModuleScope MicaSetup -Parameters @{ Installer = (Get-Process -Id $PID).Path } {
      $NewOption = {
        param([string]$Name, $Value)
        [pscustomobject]@{ Name = $Name; Value = $Value; IsResolved = $true; Expression = 'synthetic'; Method = 'Fixture::Options'; IlOffset = 0; ArrayLength = -1 }
      }
      $NewWrite = {
        param([string]$Key, [string]$Name, $Value)
        [pscustomobject]@{ Key = $Key; Name = $Name; Value = $Value; ValueKind = 1; IsResolved = $true; Method = 'Fixture::Register'; IlOffset = 16 }
      }
      $Managed = [pscustomobject]@{
        FileKind = 'Executable'
        HasOptionType = $true; HasUseOptionsMethod = $true; BuilderGeneration = 'v2'; TargetFramework = '.NETFramework,Version=v4.8'
        RequestExecutionLevel = 'admin'; UseElevated = $true; Warnings = @(); Evidence = @('synthetic hidden route')
        Resources = @([pscustomobject]@{ Name = 'resources/setups/publish.7z'; TypeCode = 33; Offset = 0; Length = 1 })
        Options = @(
          & $NewOption 'AppName' 'HiddenApp'
          & $NewOption 'KeyName' 'HiddenApp'
          & $NewOption 'ExeName' 'HiddenApp.exe'
          & $NewOption 'DisplayName' 'Hidden App'
          & $NewOption 'DisplayVersion' '2.0.0'
          & $NewOption 'Publisher' 'Example'
          & $NewOption 'IsCreateRegistryKeys' $true
          & $NewOption 'SystemComponent' $true
          & $NewOption 'IsUseRegistryPreferX86' $true
        )
        RegistryWrites = @(
          & $NewWrite 'HKEY_CURRENT_USER\Software\Classes\mica' '' 'URL:Mica Protocol'
          & $NewWrite 'HKEY_CURRENT_USER\Software\Classes\mica' 'URL Protocol' ''
          & $NewWrite 'HKEY_CURRENT_USER\Software\Classes\mica\shell\open\command' '' '"%ProgramFiles%\HiddenApp\HiddenApp.exe" "%1"'
          & $NewWrite 'HKEY_CURRENT_USER\Software\Classes\.mica' '' 'Mica.File'
          & $NewWrite 'HKEY_CURRENT_USER\Software\Classes\Mica.File\shell\open\command' '' '"%ProgramFiles%\HiddenApp\HiddenApp.exe" "%1"'
        )
      }
      Mock Get-MicaSetupManagedInfo { $Managed }
      Mock Open-MicaSetupPayloadArchive { [pscustomobject]@{ Archive = 'synthetic'; Range = $null } }
      Mock Get-MicaSetupPayloadEvidence { [pscustomobject]@{ Catalog = @(); Architectures = @(); ArchitectureInfo = $null; DependencyInfo = $null } }
      Mock Close-MicaSetupPayloadArchive {}

      $Info = Get-MicaSetupInfo -Path $Installer
      $Info.RegistryView | Should -Be '32-bit'
      $Info.ProductCode | Should -BeNullOrEmpty
      $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
      ($Info.RegistryWrites | Where-Object Name -EQ 'SystemComponent').Value | Should -Be 1
      $Info.Protocols | Should -Contain 'mica'
      $Info.FileExtensions | Should -Contain 'mica'
      ($Info.Notices -join "`n") | Should -Match 'hidden uninstall entry'
    }
  }
}

Describe 'MicaSetup payload extraction' {
  It 'extracts a selected payload file without executing it' {
    $Destination = Join-Path $TestDrive 'payload'
    $Files = @(Expand-MicaSetupInstaller -Path $Script:MicaSetupV2 -DestinationPath $Destination -Name 'MICA.exe' -CollisionAction Rename)

    $Files | Should -HaveCount 1
    $Files[0].Name | Should -Be 'MICA.exe'
    (Get-Content -LiteralPath $Files[0].FullName -AsByteStream -TotalCount 2) | Should -Be @(0x4D, 0x5A)
  }

  It 'exports a raw WPF stream resource by its resource path' {
    $Destination = Join-Path $TestDrive 'resources'
    $Files = @(Expand-MicaSetupInstaller -Path $Script:MicaSetupV2 -DestinationPath $Destination -RawResources -Name 'resources/setups/publish.7z' -CollisionAction Rename)

    $Files | Should -HaveCount 1
    $Files[0].FullName | Should -Be (Join-Path $Destination 'resources\setups\publish.7z')
    (Get-Content -LiteralPath $Files[0].FullName -AsByteStream -TotalCount 6) | Should -Be @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)
  }

  It 'extracts every payload entry and the configured uninstaller when Name is omitted' {
    $Destination = Join-Path $TestDrive 'all-payload'
    $Files = @(Expand-MicaSetupInstaller -Path $Script:MicaSetupV1 -DestinationPath $Destination)

    $Files.Count | Should -BeGreaterThan 1
    $Files.Name | Should -Contain 'MicaApp.exe'
    $Files.Name | Should -Contain 'Uninst.exe'
  }

  It 'uses Rename for internal collision handling without exposing a prompt' {
    $Destination = Join-Path $TestDrive 'collisions'
    $First = @(Expand-MicaSetupInstaller -Path $Script:MicaSetupV2 -DestinationPath $Destination -Name 'MICA.exe' -CollisionAction Rename)
    $Second = @(Expand-MicaSetupInstaller -Path $Script:MicaSetupV2 -DestinationPath $Destination -Name 'MICA.exe' -CollisionAction Rename)

    $First[0].Name | Should -Be 'MICA.exe'
    $Second[0].Name | Should -Not -Be 'MICA.exe'
  }
}

Describe 'MicaSetup malformed nested payload handling' {
  It 'retains structural identity but disables extraction when publish.7z is corrupt' {
    $CorruptInstaller = Join-Path $TestDrive 'corrupt-payload.exe'
    Copy-Item -LiteralPath $Script:MicaSetupV2 -Destination $CorruptInstaller
    $PayloadOffset = InModuleScope MicaSetup -Parameters @{ Installer = $CorruptInstaller } {
      $Stream = [IO.File]::OpenRead($Installer)
      try {
        (Get-MicaSetupManagedInfo -Stream $Stream).Resources.Where({ $_.Name -ieq 'resources/setups/publish.7z' }, 'First')[0].Offset
      } finally { $Stream.Dispose() }
    }
    $Stream = [IO.File]::Open($CorruptInstaller, 'Open', 'ReadWrite', 'Read')
    try {
      $Stream.Position = $PayloadOffset
      $Stream.Write([byte[]](0, 0, 0, 0, 0, 0))
    } finally { $Stream.Dispose() }

    Test-MicaSetupInstaller -Path $CorruptInstaller | Should -BeTrue
    $Info = Get-MicaSetupInfo -Path $CorruptInstaller
    $Info.CanExpand | Should -BeFalse
    $Info.Warnings | Should -Match 'payload archive analysis failed'
  }
}

Describe 'MicaSetup analyzer integration' {
  It 'routes strict MicaSetup evidence before generic EXE fallbacks' {
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:MicaSetupV2
    $Candidate = $Analysis.DetectedFamilies | Where-Object Family -EQ 'MicaSetup' | Select-Object -First 1
    $Result = $Analysis.ParserResults | Where-Object Name -EQ 'MicaSetup' | Select-Object -First 1

    $Candidate.Confidence | Should -Be 'high'
    $Candidate.MatchedMarkers | Should -Contain 'CLR MicaSetup configuration host + WPF resources/setups/publish.7z'
    $Result.Success | Should -BeTrue
    $Result.Result.ProductCode | Should -Be 'MicaSetup'
    $Result.Result.AppsAndFeaturesEntries.ProductCode | Should -Contain 'MicaSetup'
    $Result.Result.Notices | Should -Not -BeNullOrEmpty
    $Result.Result.SuggestedManifestFields.InstallerType | Should -Be 'exe # MicaSetup'
    $Result.Result.SuggestedManifestFields.InstallModes | Should -Be @('interactive')
    $Result.Result.SuggestedManifestFields.InstallerSwitches.Count | Should -Be 0
  }

  It 'produces a conservative WinGet installer suggestion without fabricating silent switches' {
    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.com/MicaSetup.exe' -InstallerPath $Script:MicaSetupV2 -Architecture x64

    $Suggestion.BlockingIssues | Should -BeNullOrEmpty
    $Suggestion.Installers | Should -HaveCount 1
    $Suggestion.Installers[0].InstallerType | Should -Be 'exe'
    $Suggestion.Installers[0].ProductCode | Should -Be 'MicaSetup'
    $Suggestion.Installers[0].Scope | Should -Be 'machine'
    $Suggestion.Installers[0].Contains('InstallerSwitches') | Should -BeFalse
    $Suggestion.Suggestions.FamilyDefaults.InstallerType | Should -Be 'exe # MicaSetup'
  }
}
