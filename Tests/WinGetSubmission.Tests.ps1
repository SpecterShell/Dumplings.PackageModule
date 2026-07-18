BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetSubmission.psm1') -Force
}

Describe 'WinGet submission reference version selection' {
  It 'prefers an exact rolling-channel version over the latest numeric version' {
    Select-WinGetReferencePackageVersion -AvailableVersion @('master', '3.1.0') -PackageVersion 'master' |
      Should -BeExactly 'master'
  }

  It 'falls back to the latest WinGet-sorted version for a new package version' {
    Select-WinGetReferencePackageVersion -AvailableVersion @('1.0.0', '2.0.0') -PackageVersion '3.0.0' |
      Should -BeExactly '2.0.0'
  }
}
