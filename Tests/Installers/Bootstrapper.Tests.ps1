. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global
}

Describe 'Bootstrapper command resolution' {
  It 'returns raw token extents without changing the default string contract' {
    $Line = '"C:\Program Files\setup.exe" /PaSsThRoUgH /v"/qn INSTALLDIR=\"C:\App Path\""'
    $Tokens = @(Split-BootstrapperCommandLine -CommandLine $Line -IncludeExtent)
    $Tokens.Value | Should -Be @(Split-BootstrapperCommandLine -CommandLine $Line)
    $Line.Substring($Tokens[0].Start, $Tokens[0].Length) | Should -Be '"C:\Program Files\setup.exe"'
    $Line.Substring($Tokens[1].Start + $Tokens[1].Length).TrimStart() | Should -Be '/v"/qn INSTALLDIR=\"C:\App Path\""'
    @(Split-BootstrapperCommandLine -CommandLine 'a "" b' -IncludeExtent)[1].Value | Should -Be ''
    @(Split-BootstrapperCommandLine -CommandLine '').Count | Should -Be 0
  }

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

  It 'Prefers an exact archive path over longer same-basename candidates' {
    $Result = Resolve-BootstrapperCommand -CommandLine 'msiexec.exe /i "Simple\Simple.msi" /qn' -CandidatePath @(
      'SimpleComponentPackagedFolder\Simple.msi',
      'Simple\Simple.msi'
    )

    $Result.ExecutedPayload | Should -Be 'Simple\Simple.msi'
  }

  It 'Matches a configured relative path against a supplied absolute companion path' {
    $Candidate = Join-Path $TestDrive 'payloads\x64\setup.msi'
    $Result = Resolve-BootstrapperCommand -CommandLine 'msiexec.exe /i "x64\setup.msi" /qn' -CandidatePath @($Candidate)

    $Result.ExecutedPayload | Should -Be $Candidate
    $Result.ResolutionKind | Should -Be 'Suffix'
  }

  It 'Leaves an ambiguous basename unresolved instead of choosing arbitrarily' {
    $Candidates = @(
      (Join-Path $TestDrive 'x86\setup.msi'),
      (Join-Path $TestDrive 'x64\setup.msi')
    )
    $Result = Resolve-BootstrapperCommand -CommandLine 'msiexec.exe /i setup.msi /qn' -CandidatePath $Candidates

    $Result.IsResolved | Should -BeFalse
    $Result.ResolutionKind | Should -Be 'Ambiguous'
    $Result.CandidateMatches | Should -Be $Candidates
  }
}
