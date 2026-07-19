BeforeAll {
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'General', 'Binary', 'Compression', 'Archive', 'PE', 'Bootstrapper', 'Cabinet', 'DotNetInstaller')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
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
