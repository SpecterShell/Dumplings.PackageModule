BeforeAll {
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'General', 'Binary', 'Compression', 'Archive', 'PE', 'Bootstrapper')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
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
