BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'General', 'Binary', 'Compression', 'Archive', 'PE', 'Bootstrapper', 'Cabinet', 'SevenZipSfx', 'WinRarSfx', 'IExpress', 'DotNetInstaller')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\BootstrapperParsers'
  $ProgressPreference = 'SilentlyContinue'

  function Get-BootstrapperFixture {
    param (
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$Url
    )
    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }
}

Describe 'Bootstrapper command resolution' {
  It 'Resolves payloads launched through a script host' {
    $Result = Resolve-BootstrapperCommand -CommandLine 'wscript.exe //B //NoLogo nmsetup.vbs /q' -CandidatePath @('netmon.msi', 'nmsetup.vbs')

    $Result.Launcher | Should -Be 'wscript.exe'
    $Result.ExecutedPayload | Should -Be 'nmsetup.vbs'
    $Result.ArgumentList | Should -Be @('/q')
  }

  It 'Resolves an MSI passed to msiexec' {
    $Result = Resolve-BootstrapperCommand -CommandLine 'msiexec.exe /i "payload\Product.msi" /qn' -CandidatePath @('payload\Product.msi')

    $Result.ExecutedPayload | Should -Be 'payload\Product.msi'
    $Result.ArgumentList | Should -Be @('/qn')
  }
}

Describe '7-Zip SFX configuration parser' {
  It 'Prefers ExecuteFile and preserves ExecuteParameters' {
    $Content = @'
; comment
Title="Example"
ExecuteFile="payload\Product.msi"
ExecuteParameters="/qn /norestart"
'@
    $Result = ConvertFrom-SevenZipSfxConfiguration -Content $Content -ArchiveEntry @('payload\Product.msi')

    $Result.CommandSource | Should -Be 'ExecuteFile'
    $Result.Command.ExecutedPayload | Should -Be 'payload\Product.msi'
    $Result.Command.ArgumentList | Should -Be @('/qn', '/norestart')
    $Result.PassesAdditionalArguments | Should -BeTrue
  }

  It 'Uses setup.exe when RunProgram and ExecuteFile are absent' {
    $Result = ConvertFrom-SevenZipSfxConfiguration -Content 'Title="Example"' -ArchiveEntry @('setup.exe')

    $Result.CommandSource | Should -Be 'DefaultRunProgram'
    $Result.Command.ExecutedPayload | Should -Be 'setup.exe'
  }

  It 'Preserves repeated RunProgram and AutoInstall scenarios with execution prefixes' {
    $Content = @'
RunProgram="hidcon:fm0:prepare.cmd /q"
RunProgram="nowait:setup.exe /S"
AutoInstall="payload\Product.msi /qn"
AutoInstall3="cleanup.cmd"
'@
    $Result = ConvertFrom-SevenZipSfxConfiguration -Content $Content -ArchiveEntry @('prepare.cmd', 'setup.exe', 'payload\Product.msi', 'cleanup.cmd')

    $Result.Commands.Count | Should -Be 4
    $Result.Commands[0].Detail.ExecutionPrefixes | Should -Be @('hidcon', 'fm0')
    $Result.Commands[1].Detail.Command.ExecutedPayload | Should -Be 'setup.exe'
    $Result.Commands[2].Trigger | Should -Be '-ai'
    $Result.Commands[2].Detail.Command.ExecutedPayload | Should -Be 'payload\Product.msi'
    $Result.Commands[3].Trigger | Should -Be '-ai3'
  }
}

Describe 'WinRAR GUI SFX parser' {
  It 'Parses Setup and Presetup commands from the archive comment' {
    $Result = ConvertFrom-WinRarSfxConfiguration -Content "Presetup=prepare.cmd`r`nSetup=setup.exe /w`r`nSilent=2" -ArchiveEntry @('prepare.cmd', 'setup.exe')

    $Result.Commands.Count | Should -Be 2
    $Result.Commands[0].Command.ExecutedPayload | Should -Be 'prepare.cmd'
    $Result.Commands[1].Command.ExecutedPayload | Should -Be 'setup.exe'
    $Result.Commands[1].Command.ArgumentList | Should -Be @('/w')
    $Result.Values.Silent | Should -Be '2'
  }

  It 'Reads the configured InstallShield launcher from the SCREENView SFX' {
    $Installer = Get-BootstrapperFixture -Name 'Lakes_SCREENView_4.0.1.exe' -Url 'https://www.weblakes.com/products/screen/update/Lakes_Environmental_SCREEN_View_V.4.0.1_Install.exe'
    $Result = Get-WinRarSfxInfo -Path $Installer

    $Result.Format | Should -Be 'WinRAR GUI SFX (RAR4)'
    $Result.ExecutedPayloads | Should -Contain 'setup.exe'
    $Result.Commands[0].Command.ArgumentList | Should -Contain '/w'
    $Result.NestedFiles | Should -Contain 'Lakes Environmental SCREEN View V.4.0.1.MSI'
  }
}

Describe 'IExpress parser' {
  It 'Reads script-host commands and cabinet entries from Microsoft Network Monitor' {
    $Installer = Get-BootstrapperFixture -Name 'NM34_x64.exe' -Url 'https://download.microsoft.com/download/7/1/0/7105C7FF-768E-4472-AFD5-F29108D1E383/NM34_x64.exe'
    $Result = Get-IExpressInfo -Path $Installer

    $Result.Format | Should -Be 'IExpress'
    $Result.ExecutedPayloads | Should -Contain 'nmsetup.vbs'
    $Result.NestedFiles | Should -Contain 'netmon.msi'
    $Result.NestedFiles | Should -Contain 'NetworkMonitor_Parsers.msi'
    $Result.Warnings | Should -BeNullOrEmpty
  }
}

Describe 'dotNetInstaller configuration parser' {
  It 'Returns each UI-mode command and resolves the embedded MSI' {
    $Content = @'
<?xml version="1.0" encoding="utf-8"?>
<configurations fileversion="1.2.3.4" productversion="1.2.3">
  <schema version="3.1.113.0" generator="dotNetInstaller InstallerEditor" />
  <configuration type="install" os_filter_min="win7" processor_architecture_filter="x64">
    <component type="msi" id="runtime" display_name="Runtime" package="#CABPATH\SupportFiles\Runtime.msi"
      cmdparameters="/qb-" cmdparameters_basic="/passive" cmdparameters_silent="/qn /norestart"
      selected_install="True" required_install="True" supports_install="True" processor_architecture_filter="x64" />
  </configuration>
</configurations>
'@
    $Result = ConvertFrom-DotNetInstallerConfiguration -Content $Content -ArchiveEntry @('SupportFiles\Runtime.msi')
    $Component = $Result.Components[0]

    $Result.ProductVersion | Should -Be '1.2.3'
    $Result.Generator | Should -Be 'dotNetInstaller InstallerEditor'
    $Component.Type | Should -Be 'msi'
    $Component.ProcessorArchitectureFilter | Should -Be 'x64'
    $Component.Commands.Count | Should -Be 3
    $Component.Commands[2].Mode | Should -Be 'Silent'
    $Component.Commands[2].Command.ExecutedPayload | Should -Be 'SupportFiles\Runtime.msi'
    $Component.Commands[2].Command.ArgumentList | Should -Be @('/qn', '/norestart')
  }
}
