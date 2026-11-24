. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global
  Import-CabinetDependency

  $Script:FixtureRoot = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\InstallForge'
  $Script:Baseline = Join-Path $Script:FixtureRoot '1.6.1\Controlled\Baseline.exe'
  $Script:Comprehensive = Join-Path $Script:FixtureRoot '1.6.1\Controlled\Comprehensive.exe'
  $Script:CommandOptions = Join-Path $Script:FixtureRoot '1.6.1\Controlled\CommandOptions.exe'
  $Script:CustomArpHKLM = Join-Path $Script:FixtureRoot '1.6.1\Controlled\CustomArpHKLM.exe'
  $Script:ShortcutAllUsers = Join-Path $Script:FixtureRoot '1.6.1\Controlled\ShortcutAllUsers.exe'
  $Script:Legacy122 = Join-Path $Script:FixtureRoot '2010-08-07\IFSetup.exe'

  function New-TestInstallForgeGZipTar {
    param ([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$EntryName)

    $File = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $GZip = [IO.Compression.GZipStream]::new($File, [IO.Compression.CompressionLevel]::SmallestSize, $true)
      try {
        $Tar = [Formats.Tar.TarWriter]::new($GZip, [Formats.Tar.TarEntryFormat]::Pax, $true)
        try {
          $Entry = [Formats.Tar.PaxTarEntry]::new([Formats.Tar.TarEntryType]::RegularFile, $EntryName)
          $Entry.DataStream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('payload'), $false)
          try { $Tar.WriteEntry($Entry) } finally { $Entry.DataStream.Dispose() }
        } finally {
          $Tar.Dispose()
        }
      } finally {
        $GZip.Dispose()
      }
    } finally {
      $File.Dispose()
    }
  }
}

Describe 'InstallForge compiled record parsing' {
  It 'decodes only canonical Base64 UTF-16LE path segments' {
    InModuleScope InstallForge {
      ConvertFrom-InstallForgeEncodedPath -Path 'YgBpAG4A/RQB4AGEAbQBwAGwAZQAuAGUAeABlAA==' | Should -Be (Join-Path 'bin' 'Example.exe')
      ConvertFrom-InstallForgeEncodedPath -Path 'bin\empty.empty' | Should -Be (Join-Path 'bin' 'empty.empty')
      ConvertFrom-InstallForgeEncodedPathSegment -Segment 'ordinary-name' | Should -Be 'ordinary-name'
    }
  }

  It 'decodes Registry.dat text fields and UInt32 flags without losing empty values' {
    InModuleScope InstallForge {
      $Prefix = [Text.Encoding]::UTF8.GetBytes("HKEY_CLASSES_ROOT`r`n.ifprobe`r`n`r`nInstallForge.Probe`r`n")
      $Bytes = [byte[]]::new($Prefix.Length + 4)
      [Array]::Copy($Prefix, $Bytes, $Prefix.Length)
      [BitConverter]::GetBytes([uint32]1).CopyTo($Bytes, $Prefix.Length)
      $Record = @(ConvertFrom-InstallForgeRegistryTable -Bytes $Bytes)
      $Record.Count | Should -Be 1
      $Record[0].Name | Should -Be ''
      $Record[0].Value | Should -Be 'InstallForge.Probe'
      $Record[0].RemoveOnUninstall | Should -BeTrue
    }
  }

  It 'rejects a truncated Registry.dat removal flag' {
    InModuleScope InstallForge {
      $Bytes = [Text.Encoding]::UTF8.GetBytes("HKCU`r`nSoftware\Probe`r`nName`r`nValue`r`n") + [byte[]](1, 0, 0)
      { ConvertFrom-InstallForgeRegistryTable -Bytes $Bytes } | Should -Throw '*UInt32 removal flag*'
    }
  }

  It 'keeps registry-backed custom variables unresolved for authoritative projection' {
    InModuleScope InstallForge {
      $Setup = [ordered]@{ Appname = 'Probe'; Version = '1.0'; Company = 'Vendor'; InstallDir = '[RuntimeRoot]\Probe' }
      $Constants = Get-InstallForgeConstantMap -Setup $Setup
      $Resolved = Resolve-InstallForgeConstantValue -Value '[RuntimeRoot]\Probe' -Constant $Constants
      $Constants.Contains('RuntimeRoot') | Should -BeFalse
      $Resolved | Should -Be '[RuntimeRoot]\Probe'
      Test-InstallForgeResolvedValue -Value $Resolved | Should -BeFalse
    }
  }

  It 'preserves a final empty field in a terminated fixed-record table' {
    InModuleScope InstallForge {
      $Records = @(ConvertFrom-InstallForgeFixedRecordTable -Text "Shell Execute`r`ncmd.exe`r`n/c exit 0`r`n`r`n" -FieldName Type, Command, Arguments, Options -Source 'Commands.dat')
      $Records.Count | Should -Be 1
      $Records[0].Options | Should -Be ''
    }
  }

  It 'reports runtime-only values retained in custom command records' {
    Mock Get-InstallForgeConfigurationText -ModuleName InstallForge { "Execute Application`r`n[RuntimeRoot]\probe.exe`r`n--output [RuntimeOutput]`r`n-wait`r`n" }
    InModuleScope InstallForge {
      $Diagnostics = [Collections.Generic.List[object]]::new()
      $Commands = @(Get-InstallForgeCommandRecords -Layout ([pscustomobject]@{}) -Constant ([ordered]@{}) -Diagnostics $Diagnostics)
      $Commands.Count | Should -Be 1
      $Commands[0].HasUnresolvedRuntimeValue | Should -BeTrue
      $Commands[0].UnresolvedProperties | Should -Be @('Command', 'Arguments')
      $Diagnostics.Count | Should -Be 1
      $Diagnostics[0].Id | Should -Be 'InstallForge.Command.RuntimeValueUnresolved'
    }
  }

  It 'normalizes custom ARP registry hives without inventing a registry view' {
    InModuleScope InstallForge {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKEY_CURRENT_USER'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Probe'; Name = 'DisplayName'; Value = 'Probe' }
        [pscustomobject]@{ Root = 'HKEY_CURRENT_USER'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Probe'; Name = 'DisplayVersion'; Value = '1.0' }
      )
      $Entry = @(Get-InstallForgeCustomAppsAndFeaturesEntry -RegistryWrite $Writes)
      $Entry.Count | Should -Be 1
      $Entry[0].RegistryHive | Should -Be 'HKCU'
      $Entry[0].RegistryView | Should -BeNullOrEmpty
    }
  }
}

Describe 'InstallForge payload evidence selection' {
  BeforeEach {
    Mock Export-InstallForgePayloadSelection -ModuleName InstallForge {
      param($Layout, $Selection, $MaximumExpandedBytes)
      foreach ($Item in $Selection) {
        $Parent = [IO.Path]::GetDirectoryName($Item.DestinationPath)
        if ($Parent) { $null = [IO.Directory]::CreateDirectory($Parent) }
        [IO.File]::WriteAllBytes($Item.DestinationPath, [byte[]](0))
      }
    }
    Mock Get-PEArchitectureInfo -ModuleName InstallForge {
      param($Path, $RelatedFile)
      $Architecture = [IO.Path]::GetFileName($Path) -match '64' ? 'x64' : 'x86'
      [pscustomobject]@{
        RecommendedWinGetArchitecture  = $Architecture
        RecommendedWinGetArchitectures = @($Architecture)
        SupportedArchitectures         = @($Architecture)
        Diagnostics                    = @()
      }
    }
    Mock Get-PEDependencyInfo -ModuleName InstallForge {
      param($Path, $RelatedFile)
      $Architecture = [IO.Path]::GetFileName($Path) -match '64' ? 'x64' : 'x86'
      $PackageIdentifier = "Microsoft.VCRedist.2015+.$Architecture"
      [pscustomobject]@{
        Path = $Path; CheckedFiles = @($Path) + @($RelatedFile); CheckedPEFiles = @($Path); ImportedDlls = @()
        DependsOnVCRedist = $true; DependsOnUcrt = $false; DependsOnVisualCRuntime = $true; DependsOnDotNetRuntime = $false
        VCRedistImports = @(); UcrtImports = @(); DotNetInfo = $null
        RecommendedPackageDependencyIds = @($PackageIdentifier)
        RecommendedPackageDependencies = @([pscustomobject]@{ PackageIdentifier = $PackageIdentifier })
        Diagnostics = @()
      }
    }
  }

  It 'analyzes the complete executable set when no configured main executable exists' {
    InModuleScope InstallForge {
      $Layout = [pscustomobject]@{ Payload = [pscustomobject]@{ Entries = @(
            [pscustomobject]@{ FullName = 'app\Product32.exe'; EncodedName = 'app\Product32.exe'; Length = 10 }
            [pscustomobject]@{ FullName = 'app\Product64.exe'; EncodedName = 'app\Product64.exe'; Length = 10 }
          )
        }
      }
      $Diagnostics = [Collections.Generic.List[object]]::new()
      $Evidence = Get-InstallForgePayloadEvidence -Layout $Layout -MainExecutable $null -InstallLocation $null -Diagnostics $Diagnostics

      $Evidence.AnalysisRoute | Should -Be 'PayloadExecutables'
      $Evidence.PayloadArchitectureComplete | Should -BeTrue
      $Evidence.Architectures | Should -Be @('x64', 'x86')
      $Evidence.ArchitectureInfo.RecommendedWinGetArchitecture | Should -BeNullOrEmpty
      $Evidence.DependencyInfo.RecommendedPackageDependencyIds | Should -Be @('Microsoft.VCRedist.2015+.x64', 'Microsoft.VCRedist.2015+.x86')
      $Evidence.CandidateEvidence.Count | Should -Be 2
      $Diagnostics.Id | Should -Contain 'InstallForge.Payload.ExecutableSetFallback'
    }
  }

  It 'prefers an exact configured relative path over ambiguous basenames' {
    InModuleScope InstallForge {
      $Layout = [pscustomobject]@{ Payload = [pscustomobject]@{ Entries = @(
            [pscustomobject]@{ FullName = 'bin\Product32.exe'; EncodedName = 'bin\Product32.exe'; Length = 10 }
            [pscustomobject]@{ FullName = 'tools\Product32.exe'; EncodedName = 'tools\Product32.exe'; Length = 10 }
            [pscustomobject]@{ FullName = 'tools\Helper64.exe'; EncodedName = 'tools\Helper64.exe'; Length = 10 }
          )
        }
      }
      $Diagnostics = [Collections.Generic.List[object]]::new()
      $Evidence = Get-InstallForgePayloadEvidence -Layout $Layout -MainExecutable 'C:\Program Files\Probe\bin\Product32.exe' -InstallLocation 'C:\Program Files\Probe' -Diagnostics $Diagnostics

      $Evidence.AnalysisRoute | Should -Be 'ConfiguredMain'
      $Evidence.PayloadArchitectureComplete | Should -BeTrue
      $Evidence.Architectures | Should -Be @('x86')
      $Evidence.CandidateEvidence.Path | Should -Be 'bin\Product32.exe'
      $Diagnostics.Id | Should -Not -Contain 'InstallForge.Payload.ExecutableSetFallback'
    }
  }

  It 'does not sample an executable set that exceeds the file-count limit' {
    InModuleScope InstallForge {
      $Entries = 1..($Script:InstallForgeMaximumAnalysisFiles + 1) | ForEach-Object {
        [pscustomobject]@{ FullName = "bin\Product$_.exe"; EncodedName = "bin\Product$_.exe"; Length = 1 }
      }
      $Layout = [pscustomobject]@{ Payload = [pscustomobject]@{ Entries = @($Entries) } }
      $Diagnostics = [Collections.Generic.List[object]]::new()
      $Evidence = Get-InstallForgePayloadEvidence -Layout $Layout -MainExecutable $null -InstallLocation $null -Diagnostics $Diagnostics

      $Evidence.AnalysisRoute | Should -Be 'PayloadExecutables'
      $Evidence.PayloadArchitectureComplete | Should -BeFalse
      $Evidence.Architectures | Should -BeNullOrEmpty
      $Diagnostics.Id | Should -Contain 'InstallForge.Payload.AnalysisLimit'
      Should -Invoke Export-InstallForgePayloadSelection -ModuleName InstallForge -Times 0 -Exactly
    }
  }
}

Describe 'InstallForge GZip TAR validation' {
  It 'rejects traversal introduced by decoded path segments' {
    $Parent = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('..'))
    $File = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('escape.txt'))
    $Path = Join-Path $TestDrive 'traversal.gz'
    New-TestInstallForgeGZipTar -Path $Path -EntryName "$Parent/$File"
    InModuleScope InstallForge -Parameters @{ Path = $Path } {
      param($Path)
      { Get-InstallForgeGZipTarPayloadData -Path $Path -Offset 0 -Length (Get-Item -LiteralPath $Path).Length } | Should -Throw
    }
  }

  It 'rejects a truncated GZip member' {
    $Name = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('payload.txt'))
    $Path = Join-Path $TestDrive 'complete.gz'
    $TruncatedPath = Join-Path $TestDrive 'truncated.gz'
    New-TestInstallForgeGZipTar -Path $Path -EntryName $Name
    $Bytes = [IO.File]::ReadAllBytes($Path)
    [IO.File]::WriteAllBytes($TruncatedPath, $Bytes[0..($Bytes.Length - 9)])
    InModuleScope InstallForge -Parameters @{ Path = $TruncatedPath } {
      param($Path)
      { Get-InstallForgeGZipTarPayloadData -Path $Path -Offset 0 -Length (Get-Item -LiteralPath $Path).Length } | Should -Throw
    }
  }
}

Describe 'InstallForge modern media' {
  It 'matches the controlled installed-state ARP tuple' {
    if (-not (Test-Path -LiteralPath $Script:Baseline)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:Baseline"; return }
    Get-DumplingsTestFixtureHash -Path $Script:Baseline | Should -Be '04EF98DB315933D719BA760443AAFC62E9B874B9F89FD8896023DCEF58A20DC8'
    $Info = Get-InstallForgeInfo -Path $Script:Baseline
    $Info.FormatGeneration | Should -Be 'Modern'
    $Info.ContainerRoute | Should -Be 'Resource7z'
    $Info.DisplayName | Should -Be 'Dumplings InstallForge Probe'
    $Info.DisplayVersion | Should -Be '9.8.7.6'
    $Info.Publisher | Should -Be 'Dumplings Test Vendor'
    $Info.ProductCode | Should -Be 'Dumplings InstallForge Probe'
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryHive | Should -Be 'HKLM'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\Dumplings\InstallForgeProbe'
    $Info.UninstallString | Should -Be '%ProgramFiles(x86)%\Dumplings\InstallForgeProbe\RemoveProbe'
    $Info.DisplayIcon | Should -Be $Info.UninstallString
    $Info.GeneratedUninstallerExtractable | Should -BeTrue
    $Info.GeneratedUninstallerEntry.FullName | Should -Be 'RemoveProbe.exe'
    $Info.PayloadArchitectures | Should -BeNullOrEmpty
    $Info.PayloadAnalysisRoute | Should -Be 'None'
    $Info.AppsAndFeaturesEntries.Count | Should -Be 1
    $Info.AppsAndFeaturesEntries[0].PSObject.Properties.Name | Should -Not -Contain 'UninstallString'
    $Info.InstallModes | Should -Be @('interactive')
    $Info.Diagnostics.Id | Should -Contain 'InstallForge.Installability.InteractiveOnly'
  }

  It 'decodes registry associations and operation tables from controlled media' {
    if (-not (Test-Path -LiteralPath $Script:Comprehensive)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:Comprehensive"; return }
    Get-DumplingsTestFixtureHash -Path $Script:Comprehensive | Should -Be '5C775F3A651F3CC0811B23FADF04ADF8F757A835013BD0870D500FCF7BF664C3'
    $Info = Get-InstallForgeInfo -Path $Script:Comprehensive
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryView | Should -Be '64-bit'
    $Info.DefaultInstallLocation | Should -Be '%LOCALAPPDATA%\Dumplings\InstallForgeProbe\'
    $Info.Protocols | Should -Be @('ifprobe')
    $Info.FileExtensions | Should -Be @('ifprobe')
    $Info.RegistryWrites.Count | Should -Be 6
    $Info.Shortcuts.Count | Should -Be 2
    $Info.Shortcuts.IconIndex | Should -Be @('3', '4')
    $Info.Variables.Count | Should -Be 1
    $Info.Commands.Count | Should -Be 2
    $Info.Commands.WaitForExit | Should -Be @($true, $true)
    $Info.Commands.Hidden | Should -Be @($true, $false)
    $Info.Commands | ForEach-Object { $_.UnknownOptions.Count } | Should -Be @(0, 0)
    $Info.Commands | ForEach-Object HasUnresolvedRuntimeValue | Should -Be @($false, $false)
    $Info.Shortcuts.AllUsers | Should -Be @($false, $false)
    $Info.Shortcuts.Scope | Should -Be @('user', 'user')
    $Info.Languages | Should -Be @('English', 'Deutsch')
    $Info.Requirements['Windows 11'] | Should -Be 1
  }

  It 'decodes every documented command option and an empty final option field' {
    if (-not (Test-Path -LiteralPath $Script:CommandOptions)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:CommandOptions"; return }
    Get-DumplingsTestFixtureHash -Path $Script:CommandOptions | Should -Be '5ACDD9BA836645283CA46F598984E861CC6CFEB654CC4763EC688BC7E4DAF6ED'
    $Commands = (Get-InstallForgeInfo -Path $Script:CommandOptions).Commands
    $Commands.Count | Should -Be 4
    $Commands.Type | Should -Be @('Execute Application', 'Execute Application', 'Shell Execute', 'Shell Execute')
    $Commands.WaitForExit | Should -Be @($true, $false, $true, $false)
    $Commands.Hidden | Should -Be @($true, $true, $false, $false)
    $Commands[3].Options | Should -Be ''
  }

  It 'projects compiled all-users shortcut policies onto each shortcut' {
    if (-not (Test-Path -LiteralPath $Script:ShortcutAllUsers)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:ShortcutAllUsers"; return }
    Get-DumplingsTestFixtureHash -Path $Script:ShortcutAllUsers | Should -Be 'AAB1D9E287EB7B7E0085E73F4163AF5BB80366DF8CA57A90E1F96F34B94822F7'
    $Info = Get-InstallForgeInfo -Path $Script:ShortcutAllUsers
    $Info.DesktopShortcutsForAllUsers | Should -BeTrue
    $Info.StartMenuShortcutsForAllUsers | Should -BeTrue
    $Info.Shortcuts.AllUsers | Should -Be @($true, $true)
    $Info.Shortcuts.Scope | Should -Be @('machine', 'machine')
    $Info.Shortcuts.ScopeEvidence | Should -Be @('Setup/DFA', 'Setup/SFA')
  }

  It 'keeps a REG_SZ SystemComponent custom ARP row visible in the x86 registry view' {
    if (-not (Test-Path -LiteralPath $Script:CustomArpHKLM)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:CustomArpHKLM"; return }
    Get-DumplingsTestFixtureHash -Path $Script:CustomArpHKLM | Should -Be 'D861AAE5C112FAC8587E8E20BEA599DAFDDAB629E8F66A838C0D84367E8100E0'
    $Info = Get-InstallForgeInfo -Path $Script:CustomArpHKLM
    $Info.ProductCode | Should -Be 'InstallForge.Custom.Machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.RegistryHive | Should -Be 'HKLM'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.CustomAppsAndFeaturesEntries[0].SystemComponent | Should -Be '1'
    $Info.CustomAppsAndFeaturesEntries[0].SystemComponentType | Should -Be 'String'
    $Info.CustomAppsAndFeaturesEntries[0].IsVisible | Should -BeTrue
    $Info.Diagnostics.Id | Should -Contain 'InstallForge.ARP.StringSystemComponentVisible'
  }

  It 'parses release-only GitHub assets with their published identities' -ForEach @(
    @{ Version = '1.5.0'; Hash = '98A19622366BD5FA017FF7782D35E817386B428309D62F628950A6843A8B08CA' }
    @{ Version = '1.6.0'; Hash = 'AC318047787F13F7E2F4CFD890EE6D1273498D40758FE9D8D68CC138103BC86D' }
    @{ Version = '1.6.1'; Hash = 'B0839A6426ACB3563CBBB1701179BEB7B0714ABC46C3FA79E896A6CBECD72E67' }
  ) {
    $Path = Join-Path $Script:FixtureRoot "$Version\IFInst.exe"
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Path"; return }
    Get-DumplingsTestFixtureHash -Path $Path | Should -Be $Hash
    $Info = Get-InstallForgeInfo -Path $Path
    $Info.FormatGeneration | Should -Be 'Modern'
    $Info.DisplayName | Should -Be 'InstallForge'
    $Info.DisplayVersion | Should -Be $Version
    $Info.ProductCode | Should -Be 'InstallForge'
    $Info.PayloadRoute | Should -Be 'Overlay7z'
    $Info.PayloadArchitectures | Should -Contain 'x86'
  }

  It 'catalogs the transitional 1.4 GZip TAR payload' -ForEach @(
    @{ PathName = '2022-11-28\IFSetup.exe'; Version = '1.4.2'; Hash = '57C79A11C80BA53AB4DD7EF8F4C4EBB257DD19F009145341708E3E1E538781D5'; MinimumEntries = 30 }
    @{ PathName = '2023-07-23\IFSetup.exe'; Version = '1.4.4'; Hash = '831C685F8EE0660E73089AAD194865EF2DD0E3253E51CD8C3E63CB675148A407'; MinimumEntries = 35 }
  ) {
    $Path = Join-Path $Script:FixtureRoot $PathName
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Path"; return }
    Get-DumplingsTestFixtureHash -Path $Path | Should -Be $Hash
    $Info = Get-InstallForgeInfo -Path $Path
    $Info.FormatGeneration | Should -Be 'Modern'
    $Info.ContainerRoute | Should -Be 'Resource7z'
    $Info.PayloadRoute | Should -Be 'OverlayGZipTar'
    $Info.DisplayName | Should -Be 'InstallForge'
    $Info.DisplayVersion | Should -Be $Version
    $Info.PayloadEntries.Count | Should -BeGreaterOrEqual $MinimumEntries
    $Info.Diagnostics.Id | Should -Not -Contain 'InstallForge.Extraction.PayloadMissing'
  }
}

Describe 'InstallForge legacy media' {
  It 'parses representative CAB plus ZIP generations' -ForEach @(
    @{ PathName = '2010-08-07\IFSetup.exe'; Version = '1.2.2'; ProductCode = $null; WritesArp = $false; Diagnostic = 'InstallForge.ARP.LegacyRuntimeNoRegistration' }
    @{ PathName = '2011-02-01\IFSetup.exe'; Version = '1.2.6.2'; ProductCode = 'InstallForge'; WritesArp = $true; Diagnostic = $null }
    @{ PathName = '2016-09-08\IFSetup.exe'; Version = '1.3.2'; ProductCode = 'InstallForge'; WritesArp = $true; Diagnostic = $null }
  ) {
    $Path = Join-Path $Script:FixtureRoot $PathName
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Path"; return }
    $Info = Get-InstallForgeInfo -Path $Path
    $Info.FormatGeneration | Should -Be 'Legacy'
    $Info.ContainerRoute | Should -Be 'CabinetZip'
    $Info.DisplayVersion | Should -Be $Version
    $Info.Scope | Should -Be 'machine'
    $Info.ProductCode | Should -Be $ProductCode
    $Info.WritesAppsAndFeaturesEntry | Should -Be $WritesArp
    $Info.LegacyArpRuntimeSupport | Should -Be $WritesArp
    if ($Diagnostic) { $Info.Diagnostics.Id | Should -Contain $Diagnostic }
    if ($WritesArp) {
      $Info.UninstallString | Should -BeLike '%ProgramFiles(x86)%\*\InstallForge\Uninstall.exe'
      $Info.AppsAndFeaturesEvidence[0].InstallLocation | Should -BeNullOrEmpty
    }
    $Info.PayloadEntries.Count | Should -BeGreaterThan 10
  }

  It 'retains complete legacy configuration without fabricating a missing payload catalog' {
    $Path = Join-Path $Script:FixtureRoot 'IFSetup132-2022-08-17\IFSetup132.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Path"; return }
    Get-DumplingsTestFixtureHash -Path $Path | Should -Be 'DA97FD32D01EB9ECE31358A38E19C4656177A270EAFEB15635264EA72FE40CF2'
    $Info = Get-InstallForgeInfo -Path $Path
    $Info.DisplayVersion | Should -Be '1.3.2'
    $Info.PayloadEntries | Should -BeNullOrEmpty
    $Info.ExtractedFiles | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Contain 'InstallForge.Extraction.PayloadMissing'
  }
}

Describe 'InstallForge extraction' {
  It 'extracts a selected modern installed file' {
    if (-not (Test-Path -LiteralPath $Script:Baseline)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:Baseline"; return }
    $Files = @(Expand-InstallForgeInstaller -Path $Script:Baseline -DestinationPath (Join-Path $TestDrive 'modern') -Name 'Probe.txt' -CollisionAction Rename)
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 43
    Get-DumplingsTestFixtureHash -Path $Files[0].FullName | Should -Be 'F4D8CB1A9B6840852795DCB037E63587CF9490B6FA308491BF9EAC07B02DE9A8'
  }

  It 'exports the generated modern uninstaller from its ordinary payload record' {
    if (-not (Test-Path -LiteralPath $Script:Baseline)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:Baseline"; return }
    $Files = @(Expand-InstallForgeInstaller -Path $Script:Baseline -DestinationPath (Join-Path $TestDrive 'modern-uninstaller') -Name 'RemoveProbe.exe' -CollisionAction Rename)
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 1055744
    Get-DumplingsTestFixtureHash -Path $Files[0].FullName | Should -Be '688178E1171015BE84669F6745FFA37BF2A87EA0F808B73636E648DA47BD8C45'
  }

  It 'extracts a selected transitional GZip TAR file' {
    $Path = Join-Path $Script:FixtureRoot '2023-07-23\IFSetup.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Path"; return }
    $Files = @(Expand-InstallForgeInstaller -Path $Path -DestinationPath (Join-Path $TestDrive 'transitional') -Name 'bin\ifsetupx86.exe' -CollisionAction Rename)
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 969728
    Get-DumplingsTestFixtureHash -Path $Files[0].FullName | Should -Be '2E50CC88F960D308D283EBE88CE1F8B1734D3B63687DBD05AB2417458FA2C545'
  }

  It 'extracts a selected legacy installed file' {
    if (-not (Test-Path -LiteralPath $Script:Legacy122)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:Legacy122"; return }
    $Files = @(Expand-InstallForgeInstaller -Path $Script:Legacy122 -DestinationPath (Join-Path $TestDrive 'legacy') -Name 'InstallForge.exe' -CollisionAction Rename)
    $Files.Count | Should -Be 1
    $Files[0].Length | Should -Be 1609216
    Get-DumplingsTestFixtureHash -Path $Files[0].FullName | Should -Be 'DDC0999F02EBC6656258E2DC4CB08D715D860C5B3101FC3F71D401C32B935BB7'
  }
}

Describe 'InstallForge WinGet projection' {
  It 'does not fabricate ProductCode for legacy media whose runtime writes no ARP row' {
    if (-not (Test-Path -LiteralPath $Script:Legacy122)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Script:Legacy122"; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Script:Legacy122
    $Analysis.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'ProductCode'
    $Analysis.SuggestedManifestFields.PSObject.Properties.Name | Should -Not -Contain 'AppsAndFeaturesEntries'
    $Analysis.Diagnostics.Id | Should -Contain 'InstallForge.ARP.LegacyRuntimeNoRegistration'
  }

  It 'projects ProductCode for a structurally verified legacy ARP runtime' {
    $Path = Join-Path $Script:FixtureRoot '2016-09-08\IFSetup.exe'
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because "Fixture is unavailable: $Path"; return }
    $Analysis = Get-WinGetInstallerAnalysis -Path $Path
    $Analysis.SuggestedManifestFields.ProductCode | Should -Be 'InstallForge'
    $Analysis.Diagnostics.Id | Should -Not -Contain 'InstallForge.ARP.LegacyRuntimeNoRegistration'
  }
}
