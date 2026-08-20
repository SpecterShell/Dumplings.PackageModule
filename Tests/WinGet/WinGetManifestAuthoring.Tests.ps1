. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  . (Join-Path $Script:DumplingsModuleRoot 'Index.ps1')

  function New-AuthoringTestModel {
    param ([int]$InstallerCount = 1)

    $Installers = for ($Index = 0; $Index -lt $InstallerCount; $Index++) {
      [ordered]@{
        Architecture    = $Index -eq 0 ? 'x64' : 'x86'
        InstallerType   = 'portable'
        InstallerUrl    = "https://example.test/app-$Index.exe"
        InstallerSha256 = ([char](65 + $Index)).ToString() * 64
      }
    }
    New-WinGetManifest -PackageIdentifier 'Contoso.AuthoringTest' -PackageVersion '1.2.3' `
      -DefaultLocalization ([ordered]@{
        PackageLocale    = 'en-US'
        Publisher        = 'Contoso'
        PackageName      = 'Authoring Test'
        License          = 'MIT'
        ShortDescription = 'Tests WinGet manifest authoring.'
      }) -Installer ([System.Collections.IDictionary[]]$Installers)
  }

  function New-AuthoringAnalyzerResult {
    param (
      [string]$FileType = 'PE',
      [string]$InstallerType = 'nullsoft',
      [string]$Architecture = 'x64',
      [hashtable]$Extra = @{}
    )

    $ParserResult = [ordered]@{
      Family              = 'Test family'
      InstallerType       = $InstallerType
      PackageArchitecture = $Architecture
      ProductCode         = 'Contoso.Product'
      ProductVersion      = '1.2.3'
    }
    foreach ($Key in $Extra.Keys) { $ParserResult[$Key] = $Extra[$Key] }
    [pscustomobject]@{
      DetectedFileType   = [pscustomobject]@{ Type = $FileType }
      ParserResults      = @([pscustomobject]@{ Name = 'Test parser'; Success = $true; Result = [pscustomobject]$ParserResult })
      DetectedFamilies   = @([pscustomobject]@{ Family = 'Test family' })
      FamilyCandidates   = @([pscustomobject]@{ Family = 'Test family' })
      RoutingHints       = @()
      RejectedCandidates = @()
      PortableEvidence   = $null
      Diagnostics        = @()
      SuggestedNextSteps = @()
    }
  }
}

Describe 'WinGet manifest model authoring' {
  It 'creates a complete logical model and rejects incomplete output' {
    $Manifest = New-AuthoringTestModel
    $Manifest.PSTypeNames | Should -Contain 'Dumplings.WinGet.ManifestModel'
    (Get-WinGetManifestValidationResult -Manifest $Manifest).IsValid | Should -BeTrue

    {
      New-WinGetManifest -PackageIdentifier 'Contoso.Invalid' -PackageVersion '1.0.0' `
        -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US' }) `
        -Installer ([ordered]@{ Architecture = 'x64' })
    } | Should -Throw '*incomplete or invalid*'
  }

  It 'applies InstallerDefaults to effective installers and serialized root fields' {
    $InstallerDefaults = [ordered]@{
      ProductCode     = 'Contoso.AuthoringTest'
      Protocols       = @('contoso-authoring')
      ReleaseDate     = '2026-08-10'
      UpgradeBehavior = 'install'
    }
    $Installers = @(
      [ordered]@{ Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerUrl = 'https://example.test/x64.exe'; InstallerSha256 = 'A' * 64 }
      [ordered]@{ Architecture = 'x86'; InstallerType = 'nullsoft'; InstallerUrl = 'https://example.test/x86.exe'; InstallerSha256 = 'B' * 64 }
    )
    $Manifest = New-WinGetManifest -PackageIdentifier 'Contoso.AuthoringTest' -PackageVersion '1.2.3' -DefaultLocalization ([ordered]@{ PackageLocale = 'en-US'; Publisher = 'Contoso'; PackageName = 'Authoring Test'; License = 'MIT'; ShortDescription = 'Tests WinGet manifest authoring.' }) -Installer $Installers -InstallerDefaults $InstallerDefaults
    $Documents = ConvertTo-WinGetManifestDocumentSet -Manifest $Manifest

    @($Manifest.Installers.ProductCode) | Should -Be @('Contoso.AuthoringTest', 'Contoso.AuthoringTest')
    @($Manifest.Installers | ForEach-Object { $_.Protocols[0] }) | Should -Be @('contoso-authoring', 'contoso-authoring')
    $Documents.Installer.ProductCode | Should -Be 'Contoso.AuthoringTest'
    $Documents.Installer.Protocols | Should -Be @('contoso-authoring')
    $Documents.Installer.ReleaseDate | Should -Be '2026-08-10'
    $Documents.Installer.UpgradeBehavior | Should -Be 'install'
  }

  It 'recursively patches dictionaries, replaces arrays, removes null fields, and preserves input' {
    $Manifest = New-AuthoringTestModel
    $Manifest.Installers[0]['InstallerSwitches'] = [ordered]@{ Silent = '/S'; Custom = '/old' }
    $Manifest.Installers[0]['Protocols'] = @('old', 'second')

    $Changed = Set-WinGetManifestInstaller -Manifest $Manifest -Index 0 -Patch ([ordered]@{
        InstallerSwitches = [ordered]@{ Silent = $null; Custom = '/new' }
        Protocols         = @('new')
      })

    $Manifest.Installers[0]['InstallerSwitches']['Silent'] | Should -Be '/S'
    $Changed.Installers[0]['InstallerSwitches'].Contains('Silent') | Should -BeFalse
    $Changed.Installers[0]['InstallerSwitches']['Custom'] | Should -Be '/new'
    @($Changed.Installers[0]['Protocols']) | Should -Be @('new')
  }

  It 'requires exact installer selectors and protects the final installer' {
    $Manifest = New-AuthoringTestModel -InstallerCount 2
    $Changed = Remove-WinGetManifestInstaller -Manifest $Manifest -Match ([ordered]@{ Architecture = 'x86' })
    @($Changed.Installers).Count | Should -Be 1
    @($Manifest.Installers).Count | Should -Be 2

    { Remove-WinGetManifestInstaller -Manifest $Changed -Index 0 } | Should -Throw '*last installer*'
    { Set-WinGetManifestInstaller -Manifest $Manifest -Match ([ordered]@{ InstallerType = 'portable' }) -Patch ([ordered]@{ Scope = 'user' }) } | Should -Throw '*matched 2 entries*'
  }

  It 'manages locales case-insensitively and protects the default locale' {
    $Manifest = New-AuthoringTestModel
    $Added = Add-WinGetManifestLocale -Manifest $Manifest -Localization ([ordered]@{
        PackageLocale    = 'zh-CN'
        License          = 'MIT'
        ShortDescription = 'WinGet 清单创作测试。'
      })
    $Changed = Set-WinGetManifestLocale -Manifest $Added -PackageLocale 'ZH-cn' -Patch ([ordered]@{ ShortDescription = '已更改。' })
    $Changed.Localizations[0]['ShortDescription'] | Should -Be '已更改。'
    @($Manifest.Localizations).Count | Should -Be 0

    { Add-WinGetManifestLocale -Manifest $Added -Localization ([ordered]@{ PackageLocale = 'zh-cn' }) } | Should -Throw '*already exists*'
    { Remove-WinGetManifestLocale -Manifest $Added -PackageLocale 'EN-us' } | Should -Throw '*default locale*'
    @((Remove-WinGetManifestLocale -Manifest $Changed -PackageLocale 'zh-CN').Localizations).Count | Should -Be 0
  }

  It 'sets and removes fields through RFC 6901 paths' {
    $Manifest = New-AuthoringTestModel
    $Changed = Set-WinGetManifestValue -Manifest $Manifest -Target Installer -Index 0 -Path '/InstallerSwitches/Custom' -Value '/norestart'
    $Changed.Installers[0]['InstallerSwitches']['Custom'] | Should -Be '/norestart'
    $Manifest.Installers[0].Contains('InstallerSwitches') | Should -BeFalse

    $Changed = Remove-WinGetManifestValue -Manifest $Changed -Target Installer -Index 0 -Path '/InstallerSwitches/Custom'
    $Changed.Installers[0]['InstallerSwitches'].Contains('Custom') | Should -BeFalse

    $Changed = Set-WinGetManifestValue -Manifest $Manifest -Target Package -Path '/Moniker' -Value 'authoring-test'
    $Changed.Moniker | Should -Be 'authoring-test'
  }

  It 'routes package-level installer fields through InstallerDefaults' {
    $Manifest = New-AuthoringTestModel
    $Manifest.Installers[0]['InstallerType'] = 'nullsoft'
    $Entries = @([ordered]@{ DisplayName = 'Authoring Test'; Publisher = 'Contoso'; UpgradeCode = '{AUTHORING-TEST}' })

    $Changed = Set-WinGetManifestValue -Manifest $Manifest -Target Package -Path '/AppsAndFeaturesEntries' -Value $Entries
    $Changed.InstallerDefaults['AppsAndFeaturesEntries'][0]['DisplayName'] | Should -Be 'Authoring Test'
    $Changed.Installers[0]['AppsAndFeaturesEntries'][0]['Publisher'] | Should -Be 'Contoso'
    (ConvertTo-WinGetManifestDocumentSet -Manifest $Changed).Installer.AppsAndFeaturesEntries[0].UpgradeCode | Should -Be '{AUTHORING-TEST}'

    $Removed = Remove-WinGetManifestValue -Manifest $Changed -Target Package -Path '/AppsAndFeaturesEntries'
    $Removed.InstallerDefaults.Contains('AppsAndFeaturesEntries') | Should -BeFalse
    $Removed.Installers[0].Contains('AppsAndFeaturesEntries') | Should -BeFalse
  }

  It 'rejects package paths that belong to installer or locale targets' {
    $Manifest = New-AuthoringTestModel
    { Set-WinGetManifestValue -Manifest $Manifest -Target Package -Path '/DefaultLocalization/Publisher' -Value 'Changed' } | Should -Throw '*Target Locale*'
    { Set-WinGetManifestValue -Manifest $Manifest -Target Package -Path '/UnknownField' -Value 'Changed' } | Should -Throw '*not a logical package field*'
  }

  It 'exports the authoring dictionary converter' {
    Get-Command ConvertTo-WinGetAuthoringDictionary -ErrorAction Stop | Should -Not -BeNullOrEmpty
    $Dictionary = ConvertTo-WinGetAuthoringDictionary -InputObject ([pscustomobject]@{ Name = 'value' })
    $Dictionary | Should -BeOfType ([System.Collections.IDictionary])
    $Dictionary['Name'] | Should -Be 'value'
  }

  It 'traverses existing arrays through RFC 6901 numeric segments' {
    $Manifest = New-AuthoringTestModel
    $Manifest.Installers[0]['AppsAndFeaturesEntries'] = @([ordered]@{ DisplayVersion = '1.2.3' })

    $Changed = Set-WinGetManifestValue -Manifest $Manifest -Target Installer -Index 0 -Path '/AppsAndFeaturesEntries/0/DisplayName' -Value 'Authoring Test'
    $Changed.Installers[0]['AppsAndFeaturesEntries'][0]['DisplayName'] | Should -Be 'Authoring Test'
    $Manifest.Installers[0]['AppsAndFeaturesEntries'][0].Contains('DisplayName') | Should -BeFalse

    $Changed = Remove-WinGetManifestValue -Manifest $Changed -Target Installer -Index 0 -Path '/AppsAndFeaturesEntries/0/DisplayName'
    $Changed.Installers[0]['AppsAndFeaturesEntries'][0].Contains('DisplayName') | Should -BeFalse
  }

  It 'rejects invalid array indexes and array-item removal' {
    $Manifest = New-AuthoringTestModel
    $Manifest.Installers[0]['Protocols'] = @('first', 'second')

    { Set-WinGetManifestValue -Manifest $Manifest -Target Installer -Index 0 -Path '/Protocols/2' -Value 'third' } | Should -Throw '*outside the current 2-item array*'
    { Set-WinGetManifestValue -Manifest $Manifest -Target Installer -Index 0 -Path '/Protocols/01' -Value 'changed' } | Should -Throw '*zero-based array index*'
    { Remove-WinGetManifestValue -Manifest $Manifest -Target Installer -Index 0 -Path '/Protocols/0' } | Should -Throw '*Replace the parent array*'
  }
}

Describe 'Get-WinGetInstallerManifestSuggestion' {
  BeforeEach {
    $Script:InstallerPath = Join-Path $TestDrive 'installer.bin'
    [IO.File]::WriteAllBytes($Script:InstallerPath, [byte[]](1, 2, 3, 4))
  }

  It 'projects confirmed installer families to schema-valid types without default switches' -ForEach @(
    @{ FamilyType = 'nullsoft'; Expected = 'nullsoft' }
    @{ FamilyType = 'inno'; Expected = 'inno' }
    @{ FamilyType = 'burn'; Expected = 'burn' }
    @{ FamilyType = 'exe # Advanced Installer'; Expected = 'exe' }
    @{ FamilyType = 'exe # Squirrel'; Expected = 'exe' }
  ) {
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      New-AuthoringAnalyzerResult -InstallerType $FamilyType
    }

    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/setup.exe' -InstallerPath $Script:InstallerPath
    $Suggestion.HasBlockingDiagnostics | Should -BeFalse
    $Suggestion.Installers[0]['InstallerType'] | Should -Be $Expected
    $Suggestion.Installers[0].Contains('InstallerSwitches') | Should -BeFalse
    $Suggestion.Installers[0].Contains('InstallModes') | Should -BeFalse
    $Suggestion.Installers[0].Contains('ExpectedReturnCodes') | Should -BeFalse
  }

  It 'authors WiX identity, install-location, scope, and meaningful ARP evidence' {
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      New-AuthoringAnalyzerResult -FileType MSI -InstallerType wix -Architecture x86 -Extra @{
        ProductCode           = '{PRODUCT}'
        UpgradeCode           = '{UPGRADE}'
        ProductVersion        = '2.0.0'
        Scope                 = 'machine'
        InstallLocationSwitch = 'INSTALLDIR="<INSTALLPATH>"'
      }
    }

    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/setup.msi' -InstallerPath $Script:InstallerPath -PackageVersion '2.0.1'
    $Entry = $Suggestion.Installers[0]
    $Entry['InstallerType'] | Should -Be 'wix'
    $Entry['Architecture'] | Should -Be 'x86'
    $Entry['ProductCode'] | Should -Be '{PRODUCT}'
    $Entry['Scope'] | Should -Be 'machine'
    $Entry['InstallerSwitches']['InstallLocation'] | Should -Be 'INSTALLDIR="<INSTALLPATH>"'
    $Entry['AppsAndFeaturesEntries'][0]['UpgradeCode'] | Should -Be '{UPGRADE}'
    $Entry['AppsAndFeaturesEntries'][0]['DisplayVersion'] | Should -Be '2.0.0'
  }

  It 'applies explicit overrides last and rejects UnsupportedOSArchitectures' {
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring { New-AuthoringAnalyzerResult }
    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/setup.exe' -InstallerPath $Script:InstallerPath `
      -Override ([ordered]@{ ProductCode = 'Override.Product'; UnsupportedOSArchitectures = @('arm64') })
    $Suggestion.Installers[0]['ProductCode'] | Should -Be 'Override.Product'
    $Suggestion.Installers[0].Contains('UnsupportedOSArchitectures') | Should -BeFalse
    ($Suggestion.Diagnostics | Where-Object Id -EQ 'WinGetAuthoring.UnsupportedOSArchitecturesProhibited').Message | Should -Match 'UnsupportedOSArchitectures'
    $Suggestion.HasBlockingDiagnostics | Should -BeTrue
  }

  It 'requires explicit architecture when evidence is ambiguous' {
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      New-AuthoringAnalyzerResult -Architecture $null -Extra @{ SupportedArchitectures = @('x86', 'x64') }
    }
    $Blocked = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/setup.exe' -InstallerPath $Script:InstallerPath
    ($Blocked.Diagnostics | Where-Object Id -EQ 'WinGetAuthoring.ArchitectureRequired').Message | Should -Match 'concrete.*architecture'
    $Blocked.HasBlockingDiagnostics | Should -BeTrue

    $Resolved = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/setup.exe' -InstallerPath $Script:InstallerPath -Architecture x86, x64
    @($Resolved.Installers.Architecture) | Should -Be @('x86', 'x64')
  }

  It 'authors trusted MSIX identity, platform, capabilities, and known dependencies' {
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      New-AuthoringAnalyzerResult -FileType MSIXAppX -InstallerType msix -Extra @{
        PackageFamilyName = 'Contoso.App_1234567890abc'
        SignatureSha256   = 'C' * 64
        Platform          = @('Windows.Desktop')
        MinimumOSVersion  = '10.0.17763.0'
        Capabilities      = @('internetClient')
        Dependencies      = [ordered]@{ PackageDependencies = @([ordered]@{ PackageIdentifier = 'Microsoft.WindowsAppRuntime.1.7'; MinimumVersion = '1.7.0' }) }
      }
    }

    $Entry = (Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/app.msix' -InstallerPath $Script:InstallerPath).Installers[0]
    $Entry['InstallerType'] | Should -Be 'msix'
    $Entry['PackageFamilyName'] | Should -Be 'Contoso.App_1234567890abc'
    $Entry['SignatureSha256'] | Should -Be ('C' * 64)
    $Entry['Platform'] | Should -Be @('Windows.Desktop')
    $Entry['Capabilities'] | Should -Be @('internetClient')
    $Entry['Dependencies']['PackageDependencies'][0]['PackageIdentifier'] | Should -Be 'Microsoft.WindowsAppRuntime.1.7'
  }

  It 'preserves analyzer blocking diagnostics' {
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      $Result = New-AuthoringAnalyzerResult -FileType MSIXAppX -InstallerType msix
      $Result.Diagnostics = @(
        New-InstallerDiagnostic -Id 'MSIX.Signature.Untrusted' -Source MSIX -Message 'Reject: package signature is not trusted.' -Kind Invalid -Areas Security, Installability
      )
      $Result
    }
    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/app.msix' -InstallerPath $Script:InstallerPath
    ($Suggestion.Diagnostics | Where-Object Id -EQ 'MSIX.Signature.Untrusted').Message | Should -Be 'Reject: package signature is not trusted.'
    $Suggestion.HasBlockingDiagnostics | Should -BeTrue
  }

  It 'requires a nested file when a ZIP has multiple installer candidates' {
    $ZipPath = Join-Path $TestDrive 'multiple.zip'
    $ZipSource = Join-Path $TestDrive 'multiple-source'
    $null = New-Item -Path $ZipSource -ItemType Directory
    [IO.File]::WriteAllBytes((Join-Path $ZipSource 'x86.exe'), [byte[]](1, 2))
    [IO.File]::WriteAllBytes((Join-Path $ZipSource 'x64.exe'), [byte[]](3, 4))
    Compress-Archive -Path (Join-Path $ZipSource '*') -DestinationPath $ZipPath
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      [pscustomobject]@{
        DetectedFileType = [pscustomobject]@{ Type = 'ZipArchive' }
        ParserResults = @([pscustomobject]@{ Name = 'ZIP'; Success = $true; Result = [pscustomobject]@{
              Family               = 'ZIP/archive'
              NestedInstallerFiles = @([pscustomobject]@{ FullName = 'x86.exe' }, [pscustomobject]@{ FullName = 'x64.exe' })
              PortableCandidates   = @()
              InstallerType        = 'zip'
              Diagnostics          = @()
            }
          })
        DetectedFamilies = @(); FamilyCandidates = @(); RoutingHints = @(); RejectedCandidates = @()
        PortableEvidence = $null; Diagnostics = @(); SuggestedNextSteps = @()
      }
    }
    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/multiple.zip' -InstallerPath $ZipPath
    ($Suggestion.Diagnostics | Where-Object Id -EQ 'WinGetAuthoring.Zip.CandidateAmbiguous').Message | Should -Match 'specify NestedInstallerFile'
    $Suggestion.HasBlockingDiagnostics | Should -BeTrue
  }

  It 'consumes the real ZIP analyzer envelope without StrictMode property failures' {
    $ZipPath = Join-Path $TestDrive 'documents.zip'
    $ZipSource = Join-Path $TestDrive 'documents-source'
    $null = New-Item -Path $ZipSource -ItemType Directory
    Set-Content -LiteralPath (Join-Path $ZipSource 'readme.txt') -Value 'No executable payload.'
    Compress-Archive -Path (Join-Path $ZipSource '*') -DestinationPath $ZipPath

    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/documents.zip' -InstallerPath $ZipPath

    $Suggestion.Analysis.ParserResults[0].Name | Should -Be 'ZIP/archive'
    $Suggestion.Analysis.ParserResults[0].Success | Should -BeTrue
    $Suggestion.Analysis.ParserResults[0].Result.Family | Should -Be 'ZIP/archive'
    ($Suggestion.Diagnostics | Where-Object Id -EQ 'WinGetAuthoring.Zip.NoSupportedCandidate').Message | Should -Match 'no supported nested installer or portable PE candidate'
    $Suggestion.HasBlockingDiagnostics | Should -BeTrue
  }

  It 'turns a legacy raw ZIP parser result into a blocking issue' {
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      [pscustomobject]@{
        DetectedFileType = [pscustomobject]@{ Type = 'ZipArchive' }
        ParserResults = @([pscustomobject]@{ Family = 'ZIP/archive'; NestedInstallerFiles = @(); PortableCandidates = @() })
        DetectedFamilies = @(); FamilyCandidates = @(); RoutingHints = @(); RejectedCandidates = @()
        PortableEvidence = $null; Diagnostics = @(); SuggestedNextSteps = @()
      }
    }

    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/legacy.zip' -InstallerPath $Script:InstallerPath

    ($Suggestion.Diagnostics | Where-Object Id -EQ 'WinGetAuthoring.Zip.CatalogUnavailable').Message | Should -Match 'catalog could not be parsed'
    $Suggestion.HasBlockingDiagnostics | Should -BeTrue
  }

  It 'downloads, hashes, analyzes once, and cleans its temporary file' {
    $Script:DownloadedPath = $null
    Mock Invoke-WinGetInstallerDownload -ModuleName WinGetManifestAuthoring {
      $Script:DownloadedPath = $DestinationPath
      [IO.File]::WriteAllBytes($DestinationPath, [byte[]](5, 6, 7, 8))
      [pscustomobject]@{
        Success         = $true
        DestinationPath = $DestinationPath
        ResponseHeaders = "HTTP/1.1 200 OK`r`nLast-Modified: Wed, 15 Jul 2026 08:30:00 GMT`r`n"
      }
    }
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring { New-AuthoringAnalyzerResult }

    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/setup.exe'
    $Suggestion.Installers[0]['ReleaseDate'] | Should -Be '2026-07-15'
    $Suggestion.Installers[0]['InstallerSha256'] | Should -Be (Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]](5, 6, 7, 8))) -Algorithm SHA256).Hash
    Test-Path -LiteralPath $Script:DownloadedPath | Should -BeFalse
    Should -Invoke Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring -Exactly 1
  }

  It 'selects and analyzes the sole nested ZIP installer' {
    $ZipPath = Join-Path $TestDrive 'package.zip'
    $ZipSource = Join-Path $TestDrive 'zip-source'
    $null = New-Item -Path $ZipSource -ItemType Directory
    [IO.File]::WriteAllBytes((Join-Path $ZipSource 'setup.exe'), [byte[]](9, 8, 7, 6))
    Compress-Archive -Path (Join-Path $ZipSource '*') -DestinationPath $ZipPath
    $Script:AnalyzerCalls = 0
    Mock Get-WinGetInstallerAnalysis -ModuleName WinGetManifestAuthoring {
      $Script:AnalyzerCalls++
      if ($Path -eq $ZipPath) {
        [pscustomobject]@{
          DetectedFileType = [pscustomobject]@{ Type = 'ZipArchive' }
          ParserResults = @([pscustomobject]@{ Name = 'ZIP'; Success = $true; Result = [pscustomobject]@{
                Family               = 'ZIP/archive'
                NestedInstallerFiles = @([pscustomobject]@{ FullName = 'setup.exe' })
                PortableCandidates   = @()
                Diagnostics          = @()
              }
            })
          DetectedFamilies = @(); FamilyCandidates = @(); RoutingHints = @(); RejectedCandidates = @()
          PortableEvidence = $null; Diagnostics = @(); SuggestedNextSteps = @()
        }
      } else {
        New-AuthoringAnalyzerResult -InstallerType inno
      }
    }

    $Suggestion = Get-WinGetInstallerManifestSuggestion -InstallerUrl 'https://example.test/package.zip' -InstallerPath $ZipPath
    $Suggestion.HasBlockingDiagnostics | Should -BeFalse
    $Suggestion.Installers[0]['InstallerType'] | Should -Be 'zip'
    $Suggestion.Installers[0]['NestedInstallerType'] | Should -Be 'inno'
    $Suggestion.Installers[0]['NestedInstallerFiles'][0]['RelativeFilePath'] | Should -Be 'setup.exe'
    $Script:AnalyzerCalls | Should -Be 2
  }
}

Describe 'Save-WinGetManifest and CLI' {
  It 'atomically writes, replaces stale locales, and reads the saved model' {
    $Path = Join-Path $TestDrive 'saved-manifests'
    $Manifest = New-AuthoringTestModel
    $WithLocale = Add-WinGetManifestLocale -Manifest $Manifest -Localization ([ordered]@{
        PackageLocale = 'fr-FR'; License = 'MIT'; ShortDescription = 'Test de creation de manifeste.'
      })
    $null = Save-WinGetManifest -Manifest $WithLocale -Path $Path
    (Get-ChildItem -LiteralPath $Path -Filter '*.locale.fr-FR.yaml').Count | Should -Be 1

    $Result = Save-WinGetManifest -Manifest $Manifest -Path $Path -PassThru
    $Result.Written | Should -BeTrue
    (Get-ChildItem -LiteralPath $Path -Filter '*.locale.fr-FR.yaml').Count | Should -Be 0
    (Read-WinGetManifest -Path $Path).PackageIdentifier | Should -Be 'Contoso.AuthoringTest'
  }

  It 'rejects a malformed path inside a winget-pkgs manifests tree' {
    $Manifest = New-AuthoringTestModel
    $InvalidPath = Join-Path $TestDrive 'manifests\Contoso\AuthoringTest\1.2.3'
    { Save-WinGetManifest -Manifest $Manifest -Path $InvalidPath } | Should -Throw '*package-version hierarchy*'

    $ValidPath = Join-Path $TestDrive 'manifests\c\Contoso\AuthoringTest\1.2.3'
    $Result = Save-WinGetManifest -Manifest $Manifest -Path $ValidPath -PassThru
    $Result.Written | Should -BeTrue
  }

  It 'does not write under WhatIf and refuses unexpected target contents' {
    $WhatIfPath = Join-Path $TestDrive 'what-if'
    $Result = Save-WinGetManifest -Manifest (New-AuthoringTestModel) -Path $WhatIfPath -WhatIf -PassThru
    $Result.Written | Should -BeFalse
    Test-Path -LiteralPath $WhatIfPath | Should -BeFalse

    $UnexpectedPath = Join-Path $TestDrive 'unexpected'
    $null = New-Item -Path $UnexpectedPath -ItemType Directory
    Set-Content -LiteralPath (Join-Path $UnexpectedPath 'README.txt') -Value 'unexpected'
    { Save-WinGetManifest -Manifest (New-AuthoringTestModel) -Path $UnexpectedPath } | Should -Throw '*non-manifest files*'
  }

  It 'preserves an existing target when replacement validation fails' {
    $Path = Join-Path $TestDrive 'rollback'
    $Manifest = New-AuthoringTestModel
    $null = Save-WinGetManifest -Manifest $Manifest -Path $Path
    $InvalidInstaller = [ordered]@{}
    foreach ($Key in $Manifest.Installers[0].Keys) { $InvalidInstaller[$Key] = Copy-WinGetManifestValue -Value $Manifest.Installers[0][$Key] }
    $InvalidInstaller['InstallerSha256'] = 'invalid'
    $Invalid = New-WinGetManifestModel -PackageIdentifier $Manifest.PackageIdentifier -PackageVersion $Manifest.PackageVersion `
      -ManifestVersion $Manifest.ManifestVersion -InstallerDefaults ([ordered]@{}) -Installers @($InvalidInstaller) `
      -DefaultLocalization $Manifest.DefaultLocalization -Localizations @() -SourceFormat Memory

    { Save-WinGetManifest -Manifest $Invalid -Path $Path } | Should -Throw '*validation failed*'
    (Read-WinGetManifest -Path $Path).PackageVersion | Should -Be '1.2.3'
  }

  It 'dispatches show and validate through the thin CLI' {
    $Path = Join-Path $TestDrive 'cli'
    $null = Save-WinGetManifest -Manifest (New-AuthoringTestModel) -Path $Path
    $CliPath = Join-Path $Script:DumplingsModuleRoot 'Utilities\WinGetManifest.ps1'

    $Shown = & $CliPath show -Path $Path -PassThru
    $Shown.PackageIdentifier | Should -Be 'Contoso.AuthoringTest'
    $Validated = & $CliPath validate -Path $Path -PassThru
    $Validated.IsValid | Should -BeTrue
  }
}
