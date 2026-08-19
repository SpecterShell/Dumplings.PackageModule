. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeDiscovery {
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Data\Text.psm1') -Force
}

Describe 'ConvertFrom-Base64' {
  It 'decodes a line-wrapped payload that already contains padding' {
    ("SGVs`r`nbG8=" | ConvertFrom-Base64) | Should -Be 'Hello'
  }

  It 'adds missing padding after removing line wrapping' {
    ("SGVs`nbG8" | ConvertFrom-Base64) | Should -Be 'Hello'
  }

  It 'normalizes wrapped byte-stream input consistently' {
    $Bytes = @("AAE`r`nCAwQ=" | ConvertFrom-Base64 -AsByteStream)

    $Bytes | Should -Be ([byte[]](0, 1, 2, 3, 4))
  }

  It 'rejects non-Base64 characters instead of removing them' {
    { 'SGVsbG8!' | ConvertFrom-Base64 } | Should -Throw
  }
}
