# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\General.psm1') -Force
}

Describe 'ConvertFrom-Ini' {
  It 'merges repeated sections and applies each duplicate-key policy' {
    $Content = "[Section]`r`nValue=`r`n[section]`r`nValue=second`r`nOther=kept"

    $Array = $Content | ConvertFrom-Ini
    $Array.Section.Value | Should -Be @('', 'second')
    $Array.Section.Other | Should -Be 'kept'
    ($Content | ConvertFrom-Ini -DuplicateKeyAction First).Section.Value | Should -Be ''
    ($Content | ConvertFrom-Ini -DuplicateKeyAction Last).Section.Value | Should -Be 'second'
    { $Content | ConvertFrom-Ini -DuplicateKeyAction Error } | Should -Throw '*Duplicate INI key*'
  }

  It 'decodes BOM-prefixed UTF-8 and UTF-16 files' -ForEach @(
    @{ Name = 'utf8.ini'; Encoding = [Text.UTF8Encoding]::new($true); Prefix = [Text.UTF8Encoding]::new($true).GetPreamble() }
    @{ Name = 'utf16le.ini'; Encoding = [Text.UnicodeEncoding]::new($false, $true); Prefix = [Text.UnicodeEncoding]::new($false, $true).GetPreamble() }
    @{ Name = 'utf16be.ini'; Encoding = [Text.UnicodeEncoding]::new($true, $true); Prefix = [Text.UnicodeEncoding]::new($true, $true).GetPreamble() }
  ) {
    $Path = Join-Path $TestDrive $Name
    $Body = $Encoding.GetBytes("[Metadata]`r`nName=Résumé")
    [IO.File]::WriteAllBytes($Path, [byte[]]@($Prefix + $Body))

    (ConvertFrom-Ini -Path $Path -DuplicateKeyAction Last).Metadata.Name | Should -Be 'Résumé'
  }

  It 'detects BOM-less UTF-16 in either byte order' -ForEach @(
    @{ Name = 'le.ini'; Encoding = [Text.UnicodeEncoding]::new($false, $false) }
    @{ Name = 'be.ini'; Encoding = [Text.UnicodeEncoding]::new($true, $false) }
  ) {
    $Path = Join-Path $TestDrive $Name
    [IO.File]::WriteAllBytes($Path, $Encoding.GetBytes("[Data]`r`nValue=wide"))
    (ConvertFrom-Ini -Path $Path).Data.Value | Should -Be 'wide'
  }

  It 'uses the configured legacy fallback and enforces the byte limit' {
    $Path = Join-Path $TestDrive 'legacy.ini'
    [IO.File]::WriteAllBytes($Path, [Text.Encoding]::GetEncoding(1252).GetBytes("[Data]`r`nValue=café"))

    (ConvertFrom-Ini -Path $Path -FallbackEncoding windows-1252).Data.Value | Should -Be 'café'
    { ConvertFrom-Ini -Path $Path -MaximumBytes 4 } | Should -Throw '*exceeds the configured*'
  }

  It 'preserves comments only when requested and uses case-insensitive keys' {
    $Content = "; before`r`n[Data]`r`nName=first`r`n# inside"
    $Parsed = $Content | ConvertFrom-Ini
    $Parsed._.'#Comment0' | Should -Be ' before'
    $Parsed.data.name | Should -Be 'first'
    ($Content | ConvertFrom-Ini -IgnoreComments).Data.Keys | Should -Not -Contain '#Comment0'
  }
}

Describe 'Bounded text file reading' {
  It 'lets StreamReader detect a UTF-32 byte-order mark' {
    $Path = Join-Path $TestDrive 'utf32.ini'
    $Encoding = [Text.UTF32Encoding]::new($false, $true, $true)
    [IO.File]::WriteAllBytes($Path, [byte[]]@($Encoding.GetPreamble() + $Encoding.GetBytes("[Data]`r`nValue=wide32")))

    (Read-BoundedTextFile -Path $Path) | Should -Be "[Data]`r`nValue=wide32"
    (ConvertFrom-Ini -Path $Path).Data.Value | Should -Be 'wide32'
  }

  It 'restores a caller-owned stream after the BOM-less UTF-16 probe' {
    $Bytes = [Text.Encoding]::Unicode.GetBytes("[Data]`r`nValue=wide")
    $Stream = [IO.MemoryStream]::new($Bytes, $false)
    try {
      $Stream.Position = 6
      (Get-BomlessUnicodeTextEncoding -Stream $Stream).CodePage | Should -Be 1200
      $Stream.Position | Should -Be 6
    } finally {
      $Stream.Dispose()
    }
  }

  It 'leaves BOM-prefixed encoding selection to StreamReader' {
    $Encoding = [Text.UnicodeEncoding]::new($true, $true)
    $Bytes = [byte[]]@($Encoding.GetPreamble() + $Encoding.GetBytes('value'))
    $Stream = [IO.MemoryStream]::new($Bytes, $false)
    try {
      Get-BomlessUnicodeTextEncoding -Stream $Stream | Should -BeNullOrEmpty
    } finally {
      $Stream.Dispose()
    }
  }
}
