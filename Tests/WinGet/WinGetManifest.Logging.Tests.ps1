# SPDX-License-Identifier: Apache-2.0

. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\WinGetManifestTestSetup.ps1')

Describe 'Installer-specific manifest update logging' -Tag Unit {
  InModuleScope WinGetManifestUpdate {
    BeforeEach {
      $Script:InstallerPath = Join-Path $TestDrive 'installer.exe'
      [IO.File]::WriteAllBytes($Script:InstallerPath, [byte[]](1, 2, 3))
      $Script:InstallerUrl = 'https://example.test/setup.exe'
      $Script:InstallerFiles = @{ $Script:InstallerUrl = $Script:InstallerPath }
      $Script:LogMessages = [Collections.Generic.List[object]]::new()
      $Script:Logger = { param($Message, $Level) $Script:LogMessages.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
      $Script:ParserDiagnostic = New-InstallerDiagnostic -Id Test.Parser.Warning -Source Test -Message 'Incomplete parser evidence.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode
      $Script:OldInstaller = [ordered]@{ Architecture = 'x64'; InstallerType = 'nullsoft'; InstallerUrl = $Script:InstallerUrl; ProductCode = 'Existing.Product' }
      Mock Get-WinGetInstallerReleaseDate { return $null }
      Mock Get-WinGetKnownInstallerManifestInfo {
        [pscustomobject]@{
          ParserName            = 'Test'
          DetectedInstallerType = 'nullsoft'
          InputObject           = @([pscustomobject]@{ ProductCode = 'Updated.Product'; WritesAppsAndFeaturesEntry = $true })
          Diagnostics           = @($Script:ParserDiagnostic, $Script:ParserDiagnostic)
        }
      }
      Mock Get-WinGetGenericInstallerManifestInfo {
        [pscustomobject]@{
          ParserName      = 'Test'
          InputObject     = @([pscustomobject]@{ ProductCode = 'Updated.Product'; WritesAppsAndFeaturesEntry = $true })
          Diagnostics     = @($Script:ParserDiagnostic, $Script:ParserDiagnostic)
          SelectedMsiPath = $null
        }
      }
    }

    It 'keeps each logger position, forwards levels, and accepts a bound method' {
      $Owner = [pscustomobject]@{ Messages = $Script:LogMessages }
      $Owner | Add-Member -MemberType ScriptMethod -Name Log -Value {
        param($Message, $Level)
        $this.Messages.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        return 'Logger output must not escape'
      }
      $First = New-WinGetInstallerEntryLogger -Logger $Owner.Log -Index 1 -Count 2
      $Second = New-WinGetInstallerEntryLogger -Logger $Owner.Log -Index 2 -Count 2

      @($First.Invoke('First message', 'Warning')).Count | Should -Be 0
      @($Second.Invoke('Second message', 'Info')).Count | Should -Be 0
      $Script:LogMessages.Message | Should -Be @('[Installer #1/2] First message', '[Installer #2/2] Second message')
      $Script:LogMessages.Level | Should -Be @('Warning', 'Info')
    }

    It 'labels <Mode> messages for <Count> <Family> entries and deduplicates only within an entry' -ForEach @(
      @{ Mode = 'Update'; Count = 1; Family = 'Known' }
      @{ Mode = 'Update'; Count = 2; Family = 'Generic' }
      @{ Mode = 'Replace'; Count = 3; Family = 'Known' }
      @{ Mode = 'Replace'; Count = 3; Family = 'Generic' }
    ) {
      $Template = Copy-Object $Script:OldInstaller
      if ($Family -eq 'Generic') { $Template.InstallerType = 'exe' }
      $Locales = @('en-US', 'zh-CN', 'de-DE')
      $OldInstallers = if ($Mode -eq 'Update') {
        for ($Index = 0; $Index -lt $Count; $Index++) {
          $Installer = Copy-Object $Template
          $Installer.InstallerLocale = $Locales[$Index]
          $Installer
        }
      } else { @($Template) }
      $Entries = if ($Mode -eq 'Replace') {
        for ($Index = 0; $Index -lt $Count; $Index++) { [ordered]@{ InstallerUrl = $Script:InstallerUrl; InstallerLocale = $Locales[$Index] } }
      } else { @([ordered]@{ InstallerUrl = $Script:InstallerUrl }) }

      $Arguments = @{ OldInstallers = @($OldInstallers); InstallerEntries = @($Entries); InstallerFiles = $Script:InstallerFiles; Logger = $Script:Logger }
      $Result = @(if ($Mode -eq 'Update') { Update-WinGetInstallerManifestInstallers @Arguments } else { Set-WinGetInstallerManifestInstallers @Arguments })

      $Result.Count | Should -Be $Count
      $Warnings = @($Script:LogMessages.Where({ $_.Level -eq 'Warning' }))
      $Warnings.Count | Should -Be $Count
      for ($Index = 1; $Index -le $Count; $Index++) {
        $Warnings[$Index - 1].Message | Should -BeExactly "[Installer #$Index/$Count] [Test.Parser.Warning] Test: Incomplete parser evidence."
      }
      foreach ($Message in $Script:LogMessages) { $Message.Message | Should -Match "^\[Installer #\d/$Count\] " }
      $Result.ProductCode | Should -Be (@('Updated.Product') * $Count)
      if ($Family -eq 'Known') { Should -Invoke Get-WinGetKnownInstallerManifestInfo -Exactly 1 }
    }

    It 'labels discarded authored installer values in both update modes' -ForEach @(
      @{ Mode = 'Update' }
      @{ Mode = 'Replace' }
    ) {
      $Arguments = @{
        OldInstallers         = @($Script:OldInstaller)
        InstallerEntries      = @([ordered]@{ InstallerUrl = $Script:InstallerUrl; InstallModes = @('invalid-mode') })
        InstallerFiles        = $Script:InstallerFiles
        SkipInstallerAnalysis = $true
        Logger                = $Script:Logger
      }

      $Result = @(if ($Mode -eq 'Update') { Update-WinGetInstallerManifestInstallers @Arguments } else { Set-WinGetInstallerManifestInstallers @Arguments })

      $Result[0].Contains('InstallModes') | Should -BeFalse
      $Warnings = @($Script:LogMessages.Where({ $_.Level -eq 'Warning' }))
      $Warnings.Count | Should -Be 1
      $Warnings[0].Message | Should -Match '^\[Installer #1/1\] The new value of the installer property "InstallModes" is invalid'
    }

    It 'labels blocking family mismatch diagnostics before throwing' {
      Mock Get-WinGetKnownInstallerManifestInfo {
        [pscustomobject]@{ ParserName = 'Test'; DetectedInstallerType = 'inno'; InputObject = @(); Diagnostics = @() }
      }

      { Update-WinGetInstallerManifestInstallers -OldInstallers @($Script:OldInstaller) -InstallerEntries @([ordered]@{ InstallerUrl = $Script:InstallerUrl }) -InstallerFiles $Script:InstallerFiles -Logger $Script:Logger } | Should -Throw '*detected as*inno*'

      $Errors = @($Script:LogMessages.Where({ $_.Level -eq 'Error' }))
      $Errors.Count | Should -Be 1
      $Errors[0].Message | Should -Match '^\[Installer #1/1\] \[WinGetManifestUpdate.DeclaredFamilyMismatch\]'
    }
  }
}
