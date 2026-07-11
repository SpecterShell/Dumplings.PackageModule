# SPDX-License-Identifier: MIT

BeforeAll {
  $Script:ReferenceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\.codex\skills\analyze-winget-installer\references'))
  $Script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
  $Script:SkillRoot = Join-Path $Script:RepositoryRoot '.codex\skills'
}

Describe 'Installer analysis documentation' {
  It 'has no broken relative Markdown links' {
    $Failures = [Collections.Generic.List[string]]::new()
    foreach ($File in Get-ChildItem -LiteralPath $Script:ReferenceRoot -Filter '*.md' -File) {
      $Text = Get-Content -LiteralPath $File.FullName -Raw
      foreach ($Match in [regex]::Matches($Text, '\[[^\]]+\]\((?<Target>[^)]+)\)')) {
        $Target = $Match.Groups['Target'].Value.Trim('<', '>').Split('#')[0]
        if ([string]::IsNullOrWhiteSpace($Target) -or $Target -match '^(?i:https?|mailto):') { continue }
        $Resolved = [IO.Path]::GetFullPath((Join-Path $File.DirectoryName $Target))
        if (-not (Test-Path -LiteralPath $Resolved)) { $Failures.Add("$($File.Name): $Target") }
      }
    }
    $Failures | Should -BeNullOrEmpty
  }

  It 'keeps standard focused-page headings in canonical order' {
    $Order = @('When To Use', 'Detection', 'Manifest Shape', 'Static Parsing', 'Apps & Features', 'Scope And Architecture', 'Wrapper Behavior', 'Known Examples', 'Validation Notes')
    foreach ($File in Get-ChildItem -LiteralPath $Script:ReferenceRoot -Filter 'installer-type-*.md' -File) {
      $Headings = @(Get-Content -LiteralPath $File.FullName | Where-Object { $_ -match '^##\s+' } | ForEach-Object { $_ -replace '^##\s+', '' })
      $Indexes = @($Headings | Where-Object { $_ -in $Order } | ForEach-Object { [Array]::IndexOf($Order, $_) })
      for ($Index = 1; $Index -lt $Indexes.Count; $Index++) {
        $Indexes[$Index] | Should -BeGreaterThan $Indexes[$Index - 1] -Because "$($File.Name) should follow the focused-page outline"
      }
    }
  }

  It 'does not duplicate evidence keys in the primary route table' {
    $Routing = Get-Content -LiteralPath (Join-Path $Script:ReferenceRoot 'installer-type-routing.md')
    $Rows = @($Routing | Where-Object { $_ -match '^\| `?.+\| `?installer-type-' })
    $Evidence = @($Rows | ForEach-Object { ($_ -split '\|')[1].Trim() })
    @($Evidence | Group-Object | Where-Object Count -gt 1) | Should -BeNullOrEmpty
  }

  It 'references implemented parser functions and no removed helper names' {
    $Sources = Get-ChildItem -LiteralPath (Join-Path $Script:RepositoryRoot 'Modules') -Recurse -Include '*.psm1', '*.ps1' -File
    $Implemented = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Source in $Sources) {
      $SourceText = Get-Content -LiteralPath $Source.FullName -Raw
      if ([string]::IsNullOrEmpty($SourceText)) { continue }
      foreach ($Match in [regex]::Matches($SourceText, '(?m)^function\s+(?<Name>[A-Za-z]+-[A-Za-z0-9]+)')) { $null = $Implemented.Add($Match.Groups['Name'].Value) }
    }
    $ApiText = Get-Content -LiteralPath (Join-Path $Script:ReferenceRoot 'parser-api-reference.md') -Raw
    $Documented = [regex]::Matches($ApiText, '`(?<Name>(?:Get|Read|Test|Find|Copy|Expand|Export|Import|New|Resolve)-[A-Za-z0-9]+)`') | ForEach-Object { $_.Groups['Name'].Value } | Sort-Object -Unique
    @($Documented | Where-Object { -not $Implemented.Contains($_) }) | Should -BeNullOrEmpty
    $AllDocumentation = (Get-ChildItem -LiteralPath $Script:ReferenceRoot -Filter '*.md' -File | Get-Content -Raw) -join "`n"
    $AllDocumentation | Should -Not -Match 'BinaryPatternSearch\.cs|Dumplings\.Binary\.PatternSearch'
  }

}
