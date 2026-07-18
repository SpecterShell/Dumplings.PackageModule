BeforeDiscovery {
  if (-not ([System.Management.Automation.PSTypeName]'Dumplings.Versioning.WinGetVersion').Type) {
    Add-Type -Path (Join-Path $PSScriptRoot '..\Assets\Versioning.cs')
  }
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\General.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\YamlSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestSchema.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestModel.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestSerialization.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestValidation.psm1') -Force
}

BeforeAll {
  function Write-TestSingletonManifest {
    param (
      [string]$Path,
      [string]$InstallerType = 'exe',
      [string]$InstallerFields = @'
  InstallerSwitches:
    Silent: /silent
    SilentWithProgress: /silent
'@,
      [switch]$NoHeader,
      [string]$PackageVersion = '1.0.0',
      [string]$PackageLocale = 'en-US'
    )

    $Header = if ($NoHeader) { '' } else { '# yaml-language-server: $schema=https://aka.ms/winget-manifest.singleton.1.12.0.schema.json' }
    $Content = @"
${Header}
PackageIdentifier: Test.Valid
PackageVersion: ${PackageVersion}
PackageLocale: ${PackageLocale}
Publisher: Test Publisher
PackageName: Test Package
License: MIT
ShortDescription: Test package.
InstallerType: ${InstallerType}
Installers:
- Architecture: x64
  InstallerUrl: https://example.test/setup.exe
  InstallerSha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
${InstallerFields}
ManifestType: singleton
ManifestVersion: 1.12.0
"@
    Set-Content -LiteralPath $Path -Value $Content -Encoding utf8NoBOM
  }

  function Write-TestMultiFileManifest {
    param ([string]$Path)

    $null = New-Item -ItemType Directory -Path $Path -Force
    @'
# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.12.0.schema.json
PackageIdentifier: Test.Multi
PackageVersion: 2.0.0
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.12.0
'@ | Set-Content -LiteralPath (Join-Path $Path 'Test.Multi.yaml') -Encoding utf8NoBOM
    @'
# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.12.0.schema.json
PackageIdentifier: Test.Multi
PackageVersion: 2.0.0
InstallerType: wix
Scope: machine
InstallerSwitches:
  Custom: ROOT=1
Dependencies:
  PackageDependencies:
  - PackageIdentifier: Test.Dependency
    MinimumVersion: 3.0.0
Installers:
- Architecture: x64
  InstallerUrl: https://example.test/setup.msi
  InstallerSha256: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
  InstallerSwitches:
    InstallLocation: INSTALLDIR="<INSTALLPATH>"
ManifestType: installer
ManifestVersion: 1.12.0
'@ | Set-Content -LiteralPath (Join-Path $Path 'Test.Multi.installer.yaml') -Encoding utf8NoBOM
    @'
# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.12.0.schema.json
PackageIdentifier: Test.Multi
PackageVersion: 2.0.0
PackageLocale: en-US
Publisher: Test Publisher
PackageName: Test Multi
License: MIT
ShortDescription: Test package.
ManifestType: defaultLocale
ManifestVersion: 1.12.0
'@ | Set-Content -LiteralPath (Join-Path $Path 'Test.Multi.locale.en-US.yaml') -Encoding utf8NoBOM
  }
}

Describe 'Get-WinGetManifestValidationResult' {
  It 'Validates a singleton manifest without launching winget' {
    $Path = Join-Path $TestDrive 'valid.yaml'
    Write-TestSingletonManifest -Path $Path

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeTrue -Because ($Result.Diagnostics | ConvertTo-Json -Compress -Depth 10)
    $Result.HasErrors | Should -BeFalse
    $Result.HasWarnings | Should -BeFalse
    $Result.PackageIdentifier | Should -Be 'Test.Valid'
    $Result.Files.Count | Should -Be 1
    $Result.EffectiveInstallers.Count | Should -Be 1
  }

  It 'Merges multi-file manifests and applies recursive installer inheritance' {
    $Path = Join-Path $TestDrive 'multi'
    Write-TestMultiFileManifest -Path $Path

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeTrue
    $Result.Files.Count | Should -Be 3
    $Result.MergedManifest.ManifestType | Should -Be 'merged'
    $Result.EffectiveInstallers[0].InstallerSwitches.Custom | Should -Be 'ROOT=1'
    $Result.EffectiveInstallers[0].InstallerSwitches.InstallLocation | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
    $Result.EffectiveInstallers[0].InstallerSwitches.Silent | Should -Be '/quiet /norestart'
    $Result.EffectiveInstallers[0].ExpectedReturnCodes.Count | Should -BeGreaterThan 10
    $Result.Dependencies.Count | Should -Be 1
    $Result.Dependencies[0].PackageIdentifier | Should -Be 'Test.Dependency'
    $Result.Dependencies[0].MinimumVersion | Should -Be '3.0.0'
  }

  It 'validates a logical model without persisting temporary manifests' {
    $Path = Join-Path $TestDrive 'model-input'
    Write-TestMultiFileManifest -Path $Path
    $Manifest = Read-WinGetManifest -Path $Path

    $Result = Get-WinGetManifestValidationResult -Manifest $Manifest

    $Result.IsValid | Should -BeTrue -Because ($Result.Diagnostics | ConvertTo-Json -Compress -Depth 10)
    $Result.Manifest.PSTypeNames | Should -Contain 'Dumplings.WinGet.ManifestModel'
    $Result.MergedManifest.ManifestType | Should -Be merged
    $Result.Files.Count | Should -Be 3
    $Result.EffectiveInstallers[0].InstallerSwitches.Silent | Should -Be '/quiet /norestart'
  }

  It 'Treats installer dependencies as an atomic override' {
    $Path = Join-Path $TestDrive 'dependency-override'
    Write-TestMultiFileManifest -Path $Path
    $InstallerPath = Join-Path $Path 'Test.Multi.installer.yaml'
    $Content = (Get-Content -LiteralPath $InstallerPath -Raw).Replace(
      '  InstallerSwitches:',
      "  Dependencies:`n    PackageDependencies:`n    - PackageIdentifier: Test.InstallerDependency`n  InstallerSwitches:"
    )
    Set-Content -LiteralPath $InstallerPath -Value $Content -Encoding utf8NoBOM

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeTrue
    $Result.Dependencies.PackageIdentifier | Should -Contain 'Test.InstallerDependency'
    $Result.Dependencies.PackageIdentifier | Should -Not -Contain 'Test.Dependency'
  }

  It 'Validates historical preview manifests with their legacy field names' {
    $Path = Join-Path $TestDrive 'preview.yaml'
    @'
Id: Test.Preview
Name: Test Preview
Version: 1.0.0
Publisher: Test Publisher
InstallerType: Msi
License: MIT
Installers:
- Arch: x86
  Url: https://example.test/setup.msi
  Sha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ManifestVersion: 0.1.0
'@ | Set-Content -LiteralPath $Path -Encoding utf8NoBOM

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeTrue
    $Result.PackageIdentifier | Should -Be 'Test.Preview'
    $Result.PackageVersion | Should -Be '1.0.0'
  }

  It 'Returns malformed YAML and duplicate-key failures as diagnostics' {
    $Path = Join-Path $TestDrive 'duplicate.yaml'
    @'
PackageIdentifier: Test.Duplicate
PackageIdentifier: Test.Other
'@ | Set-Content -LiteralPath $Path -Encoding utf8NoBOM

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeFalse
    $Result.Diagnostics.Id | Should -Contain 'FieldDuplicate'
    ($Result.Diagnostics | Where-Object Id -CEQ FieldDuplicate).Line | Should -Be 2
  }

  It 'Rejects nested directories in a manifest set without throwing from the result API' {
    $Path = Join-Path $TestDrive 'nested'
    $null = New-Item -ItemType Directory -Path (Join-Path $Path 'child') -Force

    { $Script:Result = Get-WinGetManifestValidationResult -Path $Path } | Should -Not -Throw
    $Script:Result.IsValid | Should -BeFalse
    $Script:Result.Diagnostics.Id | Should -Contain 'InvalidManifestPath'
  }

  It 'Detects inconsistent multi-file identity and duplicate locales' {
    $Path = Join-Path $TestDrive 'inconsistent'
    Write-TestMultiFileManifest -Path $Path
    $LocalePath = Join-Path $Path 'Test.Multi.locale.zh-CN.yaml'
    (Get-Content -LiteralPath (Join-Path $Path 'Test.Multi.locale.en-US.yaml') -Raw).
    Replace('ManifestType: defaultLocale', 'ManifestType: locale').
    Replace('PackageVersion: 2.0.0', 'PackageVersion: 3.0.0') |
      Set-Content -LiteralPath $LocalePath -Encoding utf8NoBOM

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeFalse
    $Result.Diagnostics.Id | Should -Contain 'InconsistentMultiFileManifestFieldValue'
    $Result.Diagnostics.Id | Should -Contain 'DuplicateMultiFileManifestLocale'
  }

  It 'Warns when a 1.7 or newer schema header is absent' {
    $Path = Join-Path $TestDrive 'no-header.yaml'
    Write-TestSingletonManifest -Path $Path -NoHeader

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeTrue
    $Result.HasWarnings | Should -BeTrue
    $Result.Diagnostics.Id | Should -Contain 'SchemaHeaderNotFound'
  }

  It 'Uses the nearest supported historical schema without network access' {
    Resolve-WinGetManifestSchemaVersion -ManifestVersion '1.3.9' | Should -Be '1.2.0'
    Resolve-WinGetManifestSchemaVersion -ManifestVersion '1.8.0' | Should -Be '1.7.0'
    Resolve-WinGetManifestSchemaVersion -ManifestVersion '1.27.0' | Should -Be '1.12.0'
    Resolve-WinGetManifestSchemaVersion -ManifestVersion '1.28.0' | Should -Be '1.28.0'
    (Get-WinGetManifestSchema -ManifestType singleton -ManifestVersion '1.28.0' -Raw)['$id'] | Should -Be 'https://aka.ms/winget-manifest.singleton.1.28.0.schema.json'
  }

  It 'Loads every vendored schema offline' {
    $SchemaRoot = Join-Path $PSScriptRoot '..\Assets\WinGetManifestSchemas'
    $Schemas = @(Get-ChildItem -LiteralPath $SchemaRoot -Filter '*.json' -Recurse -File)
    $Schemas.Count | Should -BeGreaterThan 50
    foreach ($Schema in $Schemas) {
      { Get-Content -LiteralPath $Schema.FullName -Raw | ConvertFrom-Json -AsHashtable | Out-Null } | Should -Not -Throw
    }
    Get-Content (Join-Path $PSScriptRoot '..\Libraries\WinGetManifestValidation.psm1') -Raw | Should -Not -Match 'winget\.exe\s+validate'
  }
}

Describe 'WinGet manifest semantic validation' {
  It 'Reports missing generic EXE switches as a warning' {
    $Path = Join-Path $TestDrive 'exe-warning.yaml'
    Write-TestSingletonManifest -Path $Path -InstallerFields ''

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.IsValid | Should -BeTrue
    $Result.Diagnostics.Id | Should -Contain 'ExeInstallerMissingSilentSwitches'
  }

  It 'Rejects blocked and malformed MSI arguments' {
    $Blocked = Join-Path $TestDrive 'blocked-msi.yaml'
    Write-TestSingletonManifest -Path $Blocked -InstallerType msi -InstallerFields "  InstallerSwitches:`n    Silent: TRANSFORMS=evil.mst`n"
    $Invalid = Join-Path $TestDrive 'invalid-msi.yaml'
    Write-TestSingletonManifest -Path $Invalid -InstallerType wix -InstallerFields "  InstallerSwitches:`n    Silent: '@INVALID'`n"

    (Get-WinGetManifestValidationResult $Blocked).Diagnostics.Id | Should -Contain 'BlockedMsiProperty'
    (Get-WinGetManifestValidationResult $Invalid).Diagnostics.Id | Should -Contain 'InvalidMsiSwitches'
  }

  It 'Rejects archive traversal, duplicate paths, and invalid portable file types' {
    $Path = Join-Path $TestDrive 'archive.yaml'
    $Fields = @'
  NestedInstallerType: portable
  NestedInstallerFiles:
  - RelativeFilePath: ..\escape.exe
    PortableCommandAlias: ..\escape
  - RelativeFilePath: ..\ESCAPE.EXE
    PortableCommandAlias: ..\ESCAPE
'@
    Write-TestSingletonManifest -Path $Path -InstallerType zip -InstallerFields $Fields

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.Diagnostics.Id | Should -Contain 'RelativeFilePathEscapesDirectory'
    $Result.Diagnostics.Id | Should -Contain 'PortableCommandAliasEscapesDirectory'
    $Result.Diagnostics.Id | Should -Contain 'DuplicateRelativeFilePath'
    $Result.Diagnostics.Id | Should -Contain 'DuplicatePortableCommandAlias'
  }

  It 'Rejects invalid locales, market combinations, and duplicate return codes' {
    InModuleScope WinGetManifestValidation {
      $Manifest = [ordered]@{ PackageVersion = '1.0.0'; PackageLocale = 'en-US' }
      $Installer = [ordered]@{
        InstallerType = 'inno'; _EffectiveInstallerType = 'inno'; Architecture = 'x64'; InstallerLocale = 'en-a'
        InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64
        Markets = [ordered]@{ AllowedMarkets = @('US'); ExcludedMarkets = @('CA') }
        InstallerSuccessCodes = @(10)
        ExpectedReturnCodes = @([ordered]@{ InstallerReturnCode = 10; ReturnResponse = 'cancelledByUser' })
      }

      $Diagnostics = @(Test-WinGetManifestSemantics -Manifest $Manifest -EffectiveInstallers @($Installer))

      $Diagnostics.Id | Should -Contain 'InvalidBcp47Value'
      $Diagnostics.Id | Should -Contain 'BothAllowedAndExcludedMarketsDefined'
      $Diagnostics.Id | Should -Contain 'DuplicateReturnCodeEntry'
    }
  }

  It 'Reports network addresses and invalid Windows feature names' {
    $Path = Join-Path $TestDrive 'network.yaml'
    $Fields = @'
  InstallerSwitches:
    Silent: /S https://example.test/config
    SilentWithProgress: /S
  Dependencies:
    WindowsFeatures:
    - invalid feature
'@
    Write-TestSingletonManifest -Path $Path -InstallerFields $Fields

    $Result = Get-WinGetManifestValidationResult -Path $Path

    $Result.Diagnostics.Id | Should -Contain 'ContainsNetworkAddress'
    $Result.Diagnostics.Id | Should -Contain 'InvalidWindowsFeatureName'
  }

  It 'Validates installer identity, reference fields, and URL-hash mappings' {
    InModuleScope WinGetManifestValidation {
      $Manifest = [ordered]@{ PackageVersion = '1.0.0'; PackageLocale = 'en-US' }
      $Installer1 = [ordered]@{
        InstallerType = 'msix'; _EffectiveInstallerType = 'msix'; Architecture = 'x64'
        InstallerUrl = 'https://example.test/one.msix'; InstallerSha256 = 'A' * 64
        ProductCode = 'Unsupported'; PackageFamilyName = 'Test_123'
        AppsAndFeaturesEntries = @([ordered]@{ DisplayName = 'Unsupported' })
      }
      $Installer2 = [ordered]@{
        InstallerType = 'msix'; _EffectiveInstallerType = 'msix'; Architecture = 'x64'; Scope = 'machine'
        InstallerUrl = 'https://example.test/one.msix'; InstallerSha256 = 'B' * 64
      }
      $Installer3 = [ordered]@{
        InstallerType = 'exe'; _EffectiveInstallerType = 'exe'; Architecture = 'arm64'
        InstallerUrl = 'https://example.test/three.exe'; InstallerSha256 = 'A' * 64
        PackageFamilyName = 'Unusual_123'; InstallerSwitches = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
      }

      $Diagnostics = @(Test-WinGetManifestSemantics -Manifest $Manifest -EffectiveInstallers @($Installer1, $Installer2, $Installer3))

      $Diagnostics.Id | Should -Contain 'DuplicateInstallerEntry'
      $Diagnostics.Id | Should -Contain 'InstallerTypeDoesNotSupportProductCode'
      $Diagnostics.Id | Should -Contain 'InstallerTypeDoesNotWriteAppsAndFeaturesEntry'
      $Diagnostics.Id | Should -Contain 'InstallerTypeDoesNotSupportPackageFamilyName'
      $Diagnostics.Id | Should -Contain 'InconsistentInstallerHash'
      $Diagnostics.Id | Should -Contain 'DuplicateInstallerHash'
    }
  }

  It 'Validates portable limits and non-portable archive file counts' {
    InModuleScope WinGetManifestValidation {
      $Manifest = [ordered]@{ PackageVersion = '1.0.0'; PackageLocale = 'en-US' }
      $Portable = [ordered]@{
        InstallerType = 'portable'; _EffectiveInstallerType = 'portable'; Architecture = 'x64'; Scope = 'user'
        InstallerUrl = 'https://example.test/tool.exe'; InstallerSha256 = 'A' * 64
        Commands = @('one', 'two'); AppsAndFeaturesEntries = @([ordered]@{}, [ordered]@{})
      }
      $Archive = [ordered]@{
        InstallerType = 'zip'; _EffectiveInstallerType = 'msi'; NestedInstallerType = 'msi'; Architecture = 'x64'
        InstallerUrl = 'https://example.test/setup.zip'; InstallerSha256 = 'B' * 64
        NestedInstallerFiles = @([ordered]@{ RelativeFilePath = 'one.msi' }, [ordered]@{ RelativeFilePath = 'two.msi' })
        InstallerSwitches = [ordered]@{ Silent = '/quiet'; SilentWithProgress = '/passive' }
      }

      $Diagnostics = @(Test-WinGetManifestSemantics -Manifest $Manifest -EffectiveInstallers @($Portable, $Archive))

      $Diagnostics.Id | Should -Contain 'ExceededCommandsLimit'
      $Diagnostics.Id | Should -Contain 'ExceededAppsAndFeaturesEntryLimit'
      $Diagnostics.Id | Should -Contain 'ScopeNotSupported'
      $Diagnostics.Id | Should -Contain 'ExceededNestedInstallerFilesLimit'
    }
  }

  It 'Validates versions, agreements, authentication, channel, and PowerShell DSC' {
    InModuleScope WinGetManifestValidation {
      $Manifest = [ordered]@{
        PackageVersion = '< 2.0'; PackageLocale = 'en-US'; Channel = 'preview'
        Agreements = @([ordered]@{})
      }
      $Installer = [ordered]@{
        InstallerType = 'exe'; _EffectiveInstallerType = 'exe'; Architecture = 'x64'
        InstallerUrl = 'https://example.test/setup.exe'; InstallerSha256 = 'A' * 64
        InstallerSwitches = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
        AppsAndFeaturesEntries = @([ordered]@{ DisplayVersion = '> 1.0' })
        Authentication = [ordered]@{ AuthenticationType = 'microsoftEntraId' }
        DesiredStateConfiguration = @([ordered]@{ Type = 'powershell' })
      }

      $Diagnostics = @(Test-WinGetManifestSemantics -Manifest $Manifest -EffectiveInstallers @($Installer))

      $Diagnostics.Id | Should -Contain 'FieldNotSupported'
      $Diagnostics.Id | Should -Contain 'ApproximateVersionNotAllowed'
      $Diagnostics.Id | Should -Contain 'InvalidFieldValue'
    }
  }
}

Describe 'Process-safe validation' {
  It 'Validates concurrently in thread-job runspaces' {
    $Path = Join-Path $TestDrive 'concurrent.yaml'
    Write-TestSingletonManifest -Path $Path
    $ModuleRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $Jobs = @(1..4 | ForEach-Object {
        Start-ThreadJob -ArgumentList $Path, $ModuleRoot -ScriptBlock {
          param ($ManifestPath, $Root)
          if (-not ([System.Management.Automation.PSTypeName]'Dumplings.Versioning.WinGetVersion').Type) {
            Add-Type -Path (Join-Path $Root 'Assets\Versioning.cs')
          }
          Import-Module (Join-Path $Root 'Libraries\General.psm1') -Force
          Import-Module (Join-Path $Root 'Libraries\YamlSchema.psm1') -Force
          Import-Module (Join-Path $Root 'Libraries\WinGetManifestSchema.psm1') -Force
          Import-Module (Join-Path $Root 'Libraries\WinGetManifestModel.psm1') -Force
          Import-Module (Join-Path $Root 'Libraries\WinGetManifestSerialization.psm1') -Force
          Import-Module (Join-Path $Root 'Libraries\WinGetManifestValidation.psm1') -Force
          (Get-WinGetManifestValidationResult -Path $ManifestPath).IsValid
        }
      })
    try {
      $Jobs | Wait-Job | Out-Null
      $Results = @($Jobs | Receive-Job)
      $Results.Count | Should -Be 4
      $Results | Should -Not -Contain $false
    } finally {
      $Jobs | Remove-Job -Force
    }
  }
}

Describe 'Differential winget validation' {
  It 'Matches native success, warning, and error classifications when winget is available' -Skip:(-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
    $ValidPath = Join-Path $TestDrive 'native-valid.yaml'
    Write-TestSingletonManifest -Path $ValidPath
    $WarningPath = Join-Path $TestDrive 'native-warning.yaml'
    Write-TestSingletonManifest -Path $WarningPath -NoHeader
    $ErrorPath = Join-Path $TestDrive 'native-error.yaml'
    Set-Content -LiteralPath $ErrorPath -Value "PackageIdentifier: One`nPackageIdentifier: Two" -Encoding utf8NoBOM

    $NativeResults = foreach ($Case in @(
        [pscustomobject]@{ Path = $ValidPath; ExpectedExit = 0 },
        [pscustomobject]@{ Path = $WarningPath; ExpectedExit = 1 },
        [pscustomobject]@{ Path = $ErrorPath; ExpectedExit = 1 }
      )) {
      $null = & winget.exe validate $Case.Path 2>&1
      [pscustomobject]@{ Path = $Case.Path; Succeeded = $LASTEXITCODE -eq 0; ExpectedExit = $Case.ExpectedExit }
    }

    $NativeResults[0].Succeeded | Should -BeTrue
    $NativeResults[1].Succeeded | Should -BeFalse
    $NativeResults[2].Succeeded | Should -BeFalse
    (Get-WinGetManifestValidationResult $ValidPath).IsValid | Should -BeTrue
    (Get-WinGetManifestValidationResult $WarningPath).HasWarnings | Should -BeTrue
    (Get-WinGetManifestValidationResult $ErrorPath).HasErrors | Should -BeTrue
  }
}

Describe 'Test-WinGetManifest' {
  It 'Emits no success output unless PassThru is specified' {
    $Path = Join-Path $TestDrive 'quiet.yaml'
    Write-TestSingletonManifest -Path $Path

    @(Test-WinGetManifest -Path $Path).Count | Should -Be 0
    (Test-WinGetManifest -Path $Path -PassThru).IsValid | Should -BeTrue
  }

  It 'Throws on errors and optionally on warnings' {
    $InvalidPath = Join-Path $TestDrive 'invalid.yaml'
    Write-TestSingletonManifest -Path $InvalidPath -PackageLocale en-a
    $WarningPath = Join-Path $TestDrive 'warning.yaml'
    Write-TestSingletonManifest -Path $WarningPath -NoHeader

    { Test-WinGetManifest -Path $InvalidPath } | Should -Throw
    { Test-WinGetManifest -Path $WarningPath } | Should -Not -Throw
    { Test-WinGetManifest -Path $WarningPath -ErrorOnWarning -WarningAction SilentlyContinue } | Should -Throw
  }
}
