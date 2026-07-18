BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Format.psm1') -Force
}

Describe 'Format-Text WinGet-safe character handling' {
  It 'removes every control character rejected by the WinGet YAML parser' {
    $BlockedCodePoints = @(0x00..0x08) + @(0x0B, 0x0C) + @(0x0E..0x1F) + @(0x7F)
    $InputText = 'A' + ( -join ($BlockedCodePoints | ForEach-Object { [char]$_ })) + 'B'

    ($InputText | Format-Text) | Should -Be 'AB'
  }

  It 'removes forbidden controls introduced by HTML entity decoding' {
    ('A&#x00;B&#x0C;C&#x1B;D&#x7F;E' | Format-Text) | Should -Be 'ABCDE'
  }

  It 'preserves line endings while converting supported Unicode newline forms to LF' {
    $InputText = "A`tB`r`nC" + [char]0x0085 + 'D' + [char]0x2028 + 'E' + [char]0x2029 + 'F'

    ($InputText | Format-Text) | Should -Be "A B`nC`nD`nE`nF"
  }

  It 'normalizes Unicode blanks and common invisible characters to ASCII spaces' {
    $CodePoints = @(
      0x00A0, 0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x1680,
      0x17B4, 0x17B5, 0x180E, 0x2000, 0x2007, 0x200B, 0x200E,
      0x202A, 0x202F, 0x205F, 0x2060, 0x2063, 0x2066, 0x2800,
      0x3000, 0x3164, 0xFEFF, 0xFFA0, 0xFFF9
    )

    foreach ($CodePoint in $CodePoints) {
      ('A' + [char]$CodePoint + 'B' | Format-Text) | Should -Be 'A B' -Because ('U+{0:X4} should be normalized' -f $CodePoint)
    }
  }

  It 'trims normalized invisible characters from the text prefix and suffix' {
    $InputText = [char]0xFEFF + [char]0x200B + 'Text' + [char]0x3000 + [char]0x2060

    ($InputText | Format-Text) | Should -Be 'Text'
  }

  It 'preserves ZWNJ and ZWJ used for script shaping and emoji sequences' {
    $InputText = 'A' + [char]0x200C + 'B' + [char]0x200D + 'C 👩‍💻'

    ($InputText | Format-Text) | Should -Be $InputText
  }
}

Describe 'Format-Text formatting regressions' {
  It 'retains CJK spacing and punctuation formatting' {
    ('当你凝视着bug，bug也凝视着你;' | Format-Text) | Should -Be '当你凝视着 bug，bug 也凝视着你。'
  }

  It 'retains list-prefix and blank-line formatting' {
    $InputText = "What's New:`n-Bug fixes;`n`n`nRecent Updates:`n1.Fixed issues;"

    ($InputText | Format-Text) | Should -Be "What's New:`n- Bug fixes;`n`nRecent Updates:`n1. Fixed issues."
  }
}
