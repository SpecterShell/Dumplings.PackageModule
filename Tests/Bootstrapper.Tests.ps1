BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\PackageModule.psd1') -Force -Global
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
