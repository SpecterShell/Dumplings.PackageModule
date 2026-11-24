. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldTestSetup.ps1')

Describe 'InstallShield MSI integration' -Tag Unit {
  It 'Should identify an official builder-generated InstallScript MSI project' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '2026R1\Differential\InstallScriptMSI\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official InstallShield builder fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info

      $Info.Variant | Should -Be 'InstallScript MSI'
      $Info.InstallShieldProjectTypeEvidence.CustomActions | Should -Contain 'ISVerifyScriptingRuntime'
      $Info.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $Info.HasInstallScript | Should -BeFalse
      $MsiInfo.InstallShieldProjectType | Should -Be 'InstallScript MSI'
      $MsiInfo.DisplayName | Should -Be 'Dumplings InstallScript MSI'
      $MsiInfo.DisplayVersion | Should -Be '1.2.3'
      $MsiInfo.InstallShieldScriptActions.Action | Should -Contain 'ISVerifyScriptingRuntime'
      $MsiInfo.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $MsiInfo.InstallShieldLauncherRequirement.SequenceConditions | Should -Contain 'NOT AFTERREBOOT AND NOT ISSETUPDRIVEN'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'ISVerifyScriptingRuntime').Sequences.Count | Should -BeGreaterThan 0
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should identify the archived InstallShield Developer 8 runtime MSI' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '8\ArchivedMedia\isscript.msi'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent InstallShield Developer 8 runtime fixture is unavailable.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.SummaryCreatingApplication | Should -Be 'InstallShield® Developer 8.0'
    $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
    $Info.ProductCode | Should -Be '{790EC520-CCCC-4810-A0FE-061633204CE4}'
    $Info.UpgradeCode | Should -Be '{F90444D7-C81B-41CE-8E5C-2AACA65325E3}'
  }

  It 'Should retain InstallScript MSI classification while analyzing its compiled action' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '2026R1\Differential\InstallScriptMSIWithAction\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official scripted InstallScript MSI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = $Info.SelectedMsiInfo

      $Info.Variant | Should -Be 'InstallScript MSI'
      $Info.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldLauncherRequirement.RequiresSetupExe | Should -BeTrue
      $MsiInfo.InstallShieldScriptInfo.EntryPoints | Should -Be 'CreateCboContents'
      $MsiInfo.InstallShieldScriptInfo.Analysis.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Function | Should -Be 'CreateCboContents'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'ISVerifyScriptingRuntime').Kind | Should -Be 'RuntimeVerifier'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover official Basic MSI InstallScript custom actions from Binary.ISSetup.dll' {
    $Fixture = Join-Path $Script:InstallShieldBuilderRoot '2026R1\Differential\InstallScriptMSIScripted\setup.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent official scripted Basic MSI fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath
      $MsiInfo = $Info.SelectedMsiInfo

      $Info.Variant | Should -Be 'Basic MSI'
      $Info.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldProjectType | Should -Be 'Basic MSI'
      $MsiInfo.HasInstallScript | Should -BeTrue
      $MsiInfo.InstallShieldScriptInfo.BinaryName | Should -Be 'ISSetup.dll'
      $MsiInfo.InstallShieldScriptInfo.EntryPoints | Should -Be @(
        'CreateCboContents', 'DllWrapper', 'QueryRegistry', 'ShowRegTestProperty'
      )
      $MsiInfo.InstallShieldScriptInfo.Analysis.ParserVersionInfo.AnalysisScope | Should -Be 'EmbeddedAction'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Target | Should -Be 'f1'
      ($MsiInfo.InstallShieldScriptActions | Where-Object Action -EQ 'CreateCboContents').Function | Should -Be 'CreateCboContents'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should not misclassify Basic MSI media merely because it carries setup.inx' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'PenSoftware_v3_9_2_2_jp_Setup.exe')
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent SHARP Pen Software fixture is unavailable.'
      return
    }

    $ExpandedPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Fixture -DestinationPath $ExpandedPath

      $Info.HasInstallScript | Should -BeTrue
      $Info.Variant | Should -Be 'Basic MSI'
      $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
      $Info.InstallScriptInfo | Should -Not -BeNullOrEmpty
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should stream an encoded zlib payload without whole-buffer parser reads' {
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-installshield-streaming'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    $FileName = 'LargePayload.msi'
    $Seed = [Text.Encoding]::UTF8.GetBytes($FileName)
    $Magic = [byte[]](0x13, 0x35, 0x86, 0x07)
    $Expected = [Text.Encoding]::UTF8.GetBytes(('InstallShield streaming regression payload.' * 4096))
    $CompressedStream = [IO.MemoryStream]::new()
    $Compressor = [IO.Compression.ZLibStream]::new($CompressedStream, [IO.Compression.CompressionLevel]::Optimal, $true)
    try {
      $Compressor.Write($Expected, 0, $Expected.Length)
    } finally {
      $Compressor.Dispose()
    }
    $Compressed = $CompressedStream.ToArray()
    $CompressedStream.Dispose()

    $Key = [byte[]]::new($Seed.Length)
    for ($Index = 0; $Index -lt $Seed.Length; $Index++) { $Key[$Index] = $Seed[$Index] -bxor $Magic[$Index % $Magic.Length] }
    $Encoded = [byte[]]::new($Compressed.Length)
    for ($Index = 0; $Index -lt $Compressed.Length; $Index++) {
      $Mixed = ((-bnot $Compressed[$Index]) -band 0xFF) -bxor $Key[($Index % 1024) % $Key.Length]
      $Encoded[$Index] = (($Mixed -shl 4) -bor ($Mixed -shr 4)) -band 0xFF
    }

    try {
      InModuleScope InstallShield -Parameters @{ ExpandedPath = $ExpandedPath; FileName = $FileName; Seed = $Seed; Encoded = $Encoded; Expected = $Expected } {
        $null = New-Item -Path $ExpandedPath -ItemType Directory -Force
        $Stream = [IO.MemoryStream]::new($Encoded)
        try {
          $Attribute = [pscustomobject]@{
            FileName          = $FileName
            Seed              = $Seed
            EncodedFlags      = 6
            FileLength        = $Encoded.Length
            IsUnicodeLauncher = 1
            DataOffset        = 0
          }
          # The record decoder must honor the operation's remaining budget and
          # remove its partial output before a caller retries with a larger one.
          { Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $ExpandedPath `
              -MaximumBytes ($Expected.Length - 1) -StreamMode } | Should -Throw '*limit*'
          Test-Path -LiteralPath (Join-Path $ExpandedPath $FileName) | Should -BeFalse
          $Stream.Position = 0
          $OutputPath = Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $ExpandedPath -StreamMode
          Test-BinarySequence -Left ([IO.File]::ReadAllBytes($OutputPath)) -Right $Expected | Should -BeTrue
        } finally {
          $Stream.Dispose()
        }
      }
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover compiled InstallScript actions from the Tenable Nessus MSI' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Nessus-10.12.3-x64.msi')
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The persistent Tenable Nessus MSI fixture is unavailable.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.InstallShieldProjectType | Should -Be 'Basic MSI'
    $Info.InstallShieldScriptInfo.HasCompiledScript | Should -BeTrue
    $Info.InstallShieldScriptInfo.EntryPoints | Should -Contain 'CheckDirPathPermissions'
    $Info.InstallShieldScriptInfo.EntryPoints | Should -Contain 'SetupProperties'
    $Info.InstallShieldScriptInfo.ExtractedFiles | Should -Contain 'Setup.inx'
    $Info.InstallShieldScriptInfo.ExtractedFiles | Should -Contain 'IsConfig.ini'
    $Info.InstallShieldScriptInfo.Analysis | Should -Not -BeNullOrEmpty
    $Info.Diagnostics.Message | Should -Not -Match 'Embedded InstallScript custom-action analysis failed'
    $Info.Diagnostics.Message | Should -Not -Match 'branch target 0 is unresolved'
    $Info.Diagnostics.Message | Should -Not -Match 'Repeated InstallScript helper calls were bounded'
    $Info.Diagnostics.Message | Should -Not -Match 'Recursive InstallScript call was bounded'
    $Info.InstallShieldScriptInfo.Analysis.OpcodeCoverage.Where({ $_.Opcode -eq 1 }).Operation | Should -Be 'Goto'
    $Info.InstallShieldScriptInfo.Diagnostics.Message | Should -Contain 'InstallScript loops, recursion, or repeated helper calls were bounded during static analysis.'
  }

  It 'Should expose bounded SMART InstallScript paths as notices rather than incomplete-analysis warnings' {
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath 'Installers/InstallShield/SMART.SMARTEducationSoftware/26.0.323.1/SMARTEducationSoftware.msi'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent SMART Education Software MSI fixture is unavailable.'
      return
    }

    $Info = Get-MsiInstallerInfo -Path $Fixture

    $Info.Diagnostics.Message | Should -Not -Match 'bounded, conservative, or malformed path'
    $Info.Diagnostics.Message | Should -Match 'loops.*bounded|unknown conditions were evaluated'
    $Info.InstallShieldScriptInfo.Diagnostics.Message | Should -Match 'loops.*bounded|unknown conditions were evaluated'
  }
}
