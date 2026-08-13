# SPDX-License-Identifier: Apache-2.0

Describe 'PackageModule manifest-backed loading' {
  BeforeAll {
    $Script:ManifestPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\PackageModule.psd1'))
    Import-Module $Script:ManifestPath -Force -Global
  }

  It 'has a valid PowerShell 7.4 module manifest' {
    $Manifest = Test-ModuleManifest -Path $Script:ManifestPath -ErrorAction Stop

    $Manifest.Name | Should -Be 'PackageModule'
    $Manifest.PowerShellVersion | Should -BeGreaterOrEqual ([version]'7.4')
  }

  It 'loads established commands through their focused implementation modules' {
    $Module = Get-Module PackageModule

    $Module.ExportedFunctions.Keys | Should -BeNullOrEmpty
    (Get-Command Get-WinGetInstallerAnalysis).ModuleName | Should -Be 'WinGetAnalysis'
    (Get-Command ConvertFrom-Ini).ModuleName | Should -Be 'Object'
    (Get-Command ConvertFrom-ProtoBuf).ModuleName | Should -Be 'ProtocolBuffers'
    (Get-Command Get-NSISInfo).ModuleName | Should -Be 'NSIS'
    (Get-Command Read-SignatureSha256FromMSIX).ModuleName | Should -Be 'MSIX'
    $DumplingsDefaultUserAgent | Should -Not -BeNullOrEmpty
  }

  It 'resolves help for commands loaded by the root module' {
    $CommandNames = Get-Module | Where-Object Path -Like "$((Get-Item (Join-Path $PSScriptRoot '..')).FullName)\Libraries\*.psm1" | ForEach-Object { $_.ExportedFunctions.Keys } | Sort-Object -Unique
    $Failures = foreach ($Name in $CommandNames) {
      try {
        $Help = Get-Help -Name $Name -ErrorAction Stop
        if ($null -eq $Help) { "${Name}: no help object was returned" }
      } catch {
        "${Name}: $($_.Exception.Message)"
      }
    }

    @($Failures) | Should -BeNullOrEmpty
  }

  It 'preserves nested help forwarding through the GitHub API proxy' {
    $Help = Get-Help -Name Invoke-GitHubApi -Full -ErrorAction Stop

    $Help.Name | Should -Be 'Invoke-RestMethod'
    @($Help.Parameters.Parameter.Name) | Should -Contain 'Uri'
  }

  It 'supports repeated imports without duplicate managed-type failures' {
    { Import-Module $Script:ManifestPath -Force -Global -ErrorAction Stop } | Should -Not -Throw
    { Import-Module $Script:ManifestPath -Force -Global -ErrorAction Stop } | Should -Not -Throw
  }

  It 'supports wildcard command discovery and function-name completion' {
    { Get-Command -Name 'Get-WinGetMan*' -ErrorAction Stop } | Should -Not -Throw
    $Completion = [System.Management.Automation.CommandCompletion]::CompleteInput('Get-WinGetMan', 13, $null)

    @($Completion.CompletionMatches.CompletionText | Where-Object { $_ -eq 'Get-WinGetManifestValidationResult' -or $_ -like '*\Get-WinGetManifestValidationResult' }) | Should -Not -BeNullOrEmpty
  }

  It 'preserves dynamic and static argument completers from implementation modules' {
    $EncodingCompletion = [System.Management.Automation.CommandCompletion]::CompleteInput('ConvertFrom-Base64 -Encoding u', 30, $null)
    $LineEndingInput = 'Convert-LineEndings -LineEnding '
    $LineEndingCompletion = [System.Management.Automation.CommandCompletion]::CompleteInput($LineEndingInput, $LineEndingInput.Length, $null)

    $EncodingCompletion.CompletionMatches.CompletionText | Should -Contain 'utf-8'
    $LineEndingCompletion.CompletionMatches.CompletionText | Should -Contain "`n"
    $LineEndingCompletion.CompletionMatches.CompletionText | Should -Contain "`r`n"
  }

  It 'exposes each function through only its implementation module' {
    @(Get-Command Get-InnoInfo -All) | Should -HaveCount 1
    (Get-Command Get-InnoInfo).ModuleName | Should -Be 'Inno'
    (Get-Command 'Inno\Get-InnoInfo').ModuleName | Should -Be 'Inno'
  }

  It 'retains the default manifest schema version after global parent-module imports' {
    $Schema = Get-WinGetManifestSchema -ManifestType version

    $Schema['$id'] | Should -Be 'https://aka.ms/winget-manifest.version.1.12.0.schema.json'
    $ManifestVersion | Should -Be '1.12.0'
  }

  It 'retains internal state for the globally loaded installer cache' {
    $UpdateModule = Get-Module WinGetManifestUpdate
    $InternalCache = & $UpdateModule { $Script:WinGetSharedInstallerFiles }

    $InternalCache | Should -BeOfType ([System.Collections.IDictionary])
    [object]::ReferenceEquals($InternalCache, $WinGetInstallerFiles) | Should -BeTrue
  }

  It 'loads executable wrapper families as separate modules' {
    Get-Module Bootstrapper | Should -Not -BeNullOrEmpty
    Get-Module DotNetInstaller | Should -Not -BeNullOrEmpty
    Get-Module IExpress | Should -Not -BeNullOrEmpty
    Get-Module SevenZipSfx | Should -Not -BeNullOrEmpty
    Get-Module WinRarSfx | Should -Not -BeNullOrEmpty
    Get-Module WrapperInstallers | Should -BeNullOrEmpty
  }

  It 'loads focused data and provider-neutral infrastructure modules' {
    foreach ($Name in @('Text', 'Format', 'HTML', 'Conversion', 'Object')) { Get-Module $Name | Should -Not -BeNullOrEmpty }
    foreach ($Name in @('ARP', 'InstallerAnalyzer', 'PEArchitecture', 'PEDependency')) { (Get-Module $Name).Path | Should -Match '[\\/]Libraries[\\/]Infrastructure[\\/]' }

    (Get-Module Text).ExportedFunctions.Keys | Should -Not -Contain 'Format-Text'
    (Get-Module Text).ExportedFunctions.Keys | Should -Not -Contain 'Get-TextContent'
    (Get-Module Text).ExportedFunctions.Keys | Should -Contain 'ConvertTo-UnescapedUri'
    (Get-Module Text).ExportedFunctions.Keys | Should -Contain 'ConvertTo-Https'
    (Get-Module Format).ExportedFunctions.Keys | Should -Contain 'Format-Text'
    (Get-Module HTML).ExportedFunctions.Keys | Should -Contain 'Get-TextContent'
    (Get-Module Object).ExportedFunctions.Keys | Should -Contain 'ConvertFrom-Ini'
    (Get-Module Web).ExportedFunctions.Keys | Should -Not -Contain 'ConvertTo-UnescapedUri'
    (Get-Module Web).ExportedFunctions.Keys | Should -Not -Contain 'ConvertTo-Https'
  }

  It 'preserves the relocated text conversion behavior' {
    'https%3A%2F%2Fexample.test%2Fa%20b' | ConvertTo-UnescapedUri | Should -Be 'https://example.test/a b'
    'http://example.test/path' | ConvertTo-Https | Should -Be 'https://example.test/path'
    'HTTP://example.test/path' | ConvertTo-Https | Should -Be 'HTTP://example.test/path'
  }
}

Describe 'Provider-neutral installer analysis projection' {
  BeforeAll {
    $Script:ManifestPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\PackageModule.psd1'))
    Import-Module $Script:ManifestPath -Force -Global
  }

  It 'keeps generic evidence free of WinGet family defaults' {
    $Path = Join-Path $TestDrive 'paquet-marker.exe'
    [IO.File]::WriteAllText($Path, 'MZ Paquet Builder Setup G.D.G. Software installpackbuilder.com')

    $Generic = Get-InstallerAnalysis -Path $Path
    $WinGet = Get-WinGetInstallerAnalysis -Path $Path
    $GenericRoute = $Generic.RoutingHints | Where-Object Family -EQ 'Paquet Builder' | Select-Object -First 1
    $WinGetRoute = $WinGet.RoutingHints | Where-Object Family -EQ 'Paquet Builder' | Select-Object -First 1

    $GenericRoute.Family | Should -Be 'Paquet Builder'
    $GenericRoute.SuggestedManifestFields.InstallerSwitches.Silent | Should -BeNullOrEmpty
    $WinGetRoute.SuggestedManifestFields.InstallerSwitches.Silent | Should -Be '/s'
  }
}
